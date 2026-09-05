package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// check runs the config through --check. A config with a [bootstrap-resolver]
// makes run() replace the process-wide net.DefaultResolver, which would
// otherwise outlive the test and point every later lookup in the package at
// whatever address that config used.
func check(t *testing.T, content string) error {
	t.Helper()
	defaultResolver := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = defaultResolver })
	name := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(name, []byte(content), 0600))
	return run(options{check: true}, []string{name})
}

// Routers are the one part of the pipeline the test below doesn't build. The
// default route here points back at the resolver the first route uses, so the
// duplicate ids are not adjacent.
func TestCheckValidConfig(t *testing.T) {
	require.NoError(t, check(t, `
[resolvers.upstream]
address = "127.0.0.1:5399"
protocol = "udp"

[resolvers.other]
address = "127.0.0.1:5398"
protocol = "udp"

[routers.router]
routes = [
  {type = "A", resolver = "upstream"},
  {type = "AAAA", resolver = "other"},
  {resolver = "upstream"},
]

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "router"
`))
}

// A group can reach the same resolver through more than one option. Both
// references produce the same DAG edge, which the DAG rejects as a duplicate
// unless they are deduplicated first.
func TestCheckGroupReferencesResolverTwice(t *testing.T) {
	require.NoError(t, check(t, `
[resolvers.upstream]
address = "127.0.0.1:5399"
protocol = "udp"

[groups.blocked]
type = "blocklist-v2"
resolvers = ["upstream"]
allowlist-resolver = "upstream"
blocklist-format = "domain"
blocklist = ["evil.com"]
allowlist = ["good.com"]

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "blocked"
`))
}

func TestCheckInvalidConfig(t *testing.T) {
	err := check(t, `
[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "does-not-exist"`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-existent resolver")
}

// --check has to be safe to run against the config of an instance that is
// already serving, which means it must not bind the listener address, and
// must not run the shutdown handlers: a memory cache backend writes its
// content to file on close, which would flush an empty cache over the
// running instance's file.
func TestCheckSafeAgainstRunningInstance(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	cacheFile := filepath.Join(t.TempDir(), "cache.db")
	content := []byte("cache content written by a running instance")
	require.NoError(t, os.WriteFile(cacheFile, content, 0600))

	err = check(t, `
[resolvers.upstream]
address = "127.0.0.1:5399"
protocol = "udp"

[groups.cached]
type = "cache"
resolvers = ["upstream"]
backend = {type = "memory", filename = "`+cacheFile+`", save-interval = 3600}

[listeners.local-udp]
address = "`+conn.LocalAddr().String()+`"
protocol = "udp"
resolver = "cached"
`)
	require.NoError(t, err, "--check bound an address that is already in use")

	after, err := os.ReadFile(cacheFile)
	require.NoError(t, err)
	require.Equal(t, content, after, "--check overwrote the cache file")
}

// The bootstrap-resolver is built before the dependency graph, so referencing
// it by ID has to be wired up separately from the other elements.
func TestCheckBootstrapResolverAsResolver(t *testing.T) {
	require.NoError(t, check(t, `
[bootstrap-resolver]
address = "127.0.0.1:5399"
protocol = "udp"

[resolvers.upstream]
address = "127.0.0.1:5398"
protocol = "udp"

[groups.cached]
type = "cache"
resolvers = ["bootstrap-resolver"]

[routers.router]
routes = [
  {name = '\.com\.$', resolver = "bootstrap-resolver"},
  {type = "A", resolver = "cached"},
  {resolver = "upstream"},
]

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "router"

[listeners.direct]
address = "127.0.0.1:5398"
protocol = "udp"
resolver = "bootstrap-resolver"
`))
}

// Defining an element with the reserved ID would build a second resolver and
// replace the bootstrap one in the map, so it has to be rejected.
func TestCheckBootstrapResolverIDReserved(t *testing.T) {
	for _, tc := range []struct{ name, section string }{
		{"resolver", `
[resolvers.bootstrap-resolver]
address = "127.0.0.1:5398"
protocol = "udp"`},
		{"group", `
[groups.bootstrap-resolver]
type = "cache"
resolvers = ["upstream"]`},
		{"router", `
[routers.bootstrap-resolver]
routes = [{resolver = "upstream"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := check(t, `
[bootstrap-resolver]
address = "127.0.0.1:5399"
protocol = "udp"

[resolvers.upstream]
address = "127.0.0.1:5398"
protocol = "udp"
`+tc.section+`

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "upstream"
`)
			require.Error(t, err)
			require.Contains(t, err.Error(), "is reserved")
		})
	}
}

// Without a [bootstrap-resolver] section the ID is not special and a reference
// to it is a typo like any other.
func TestCheckBootstrapResolverNotDefined(t *testing.T) {
	err := check(t, `
[resolvers.upstream]
address = "127.0.0.1:5398"
protocol = "udp"

[routers.router]
routes = [{resolver = "bootstrap-resolver"}]

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "router"
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "'bootstrap-resolver' is unknown")
}

// idle-timeout moved from the doh sub-table to the resolver level. Both forms
// have to keep working, but not together, since zero is indistinguishable from
// unset and a silent winner would ignore what the user wrote.
func TestCheckIdleTimeout(t *testing.T) {
	config := func(resolverOpt, dohOpt string) string {
		return `
[resolvers.upstream]
address = "https://dns.google/dns-query"
protocol = "doh"
` + resolverOpt + `
` + dohOpt + `

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "upstream"
`
	}

	t.Run("resolver level", func(t *testing.T) {
		require.NoError(t, check(t, config(`idle-timeout = 60`, ``)))
	})
	t.Run("deprecated doh form", func(t *testing.T) {
		require.NoError(t, check(t, config(``, `doh = { idle-timeout = 60 }`)))
	})
	t.Run("neither", func(t *testing.T) {
		require.NoError(t, check(t, config(``, ``)))
	})
	t.Run("both is an error", func(t *testing.T) {
		err := check(t, config(`idle-timeout = 60`, `doh = { idle-timeout = 30 }`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "both at the resolver level and under doh")
	})
	t.Run("negative is an error", func(t *testing.T) {
		err := check(t, config(`idle-timeout = -1`, ``))
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not be negative")
	})
}

// The option applies to every protocol, not just the two it started on.
func TestCheckIdleTimeoutAllProtocols(t *testing.T) {
	for _, tc := range []struct{ protocol, address string }{
		{"udp", "8.8.8.8:53"},
		{"tcp", "8.8.8.8:53"},
		{"dot", "dns.google:853"},
		{"dtls", "8.8.8.8:853"},
		{"doq", "dns.adguard.com:8853"},
		{"doh", "https://dns.google/dns-query"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			require.NoError(t, check(t, `
[resolvers.upstream]
address = "`+tc.address+`"
protocol = "`+tc.protocol+`"
idle-timeout = 45

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "upstream"
`))
		})
	}
}

// DTLS pre-shared keys, on both resolvers and listeners.
func TestCheckDTLSPSK(t *testing.T) {
	listener := func(opts string) string {
		return `
[listeners.local-dtls]
address = "127.0.0.1:5399"
protocol = "dtls"
resolver = "upstream"
` + opts + `

[resolvers.upstream]
address = "8.8.8.8:53"
protocol = "udp"
`
	}
	resolver := func(opts string) string {
		return `
[resolvers.upstream]
address = "8.8.8.8:853"
protocol = "dtls"
` + opts + `

[listeners.local-udp]
address = "127.0.0.1:5399"
protocol = "udp"
resolver = "upstream"
`
	}

	t.Run("listener psk", func(t *testing.T) {
		require.NoError(t, check(t, listener(`psk = "0102030405060708"`)))
	})
	t.Run("listener psk with identity", func(t *testing.T) {
		require.NoError(t, check(t, listener(`psk = "0102030405060708"
psk-identity = "server"`)))
	})
	t.Run("resolver psk with identity", func(t *testing.T) {
		require.NoError(t, check(t, resolver(`psk = "0102030405060708"
psk-identity = "client"`)))
	})
	t.Run("resolver psk without identity", func(t *testing.T) {
		err := check(t, resolver(`psk = "0102030405060708"`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "psk-identity is required")
	})
	t.Run("identity without a key", func(t *testing.T) {
		err := check(t, listener(`psk-identity = "server"`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "psk-identity requires psk")
	})
	t.Run("key is not hex", func(t *testing.T) {
		err := check(t, listener(`psk = "not-hex"`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "hex-encoded")
	})
	t.Run("psk with a certificate", func(t *testing.T) {
		err := check(t, listener(`psk = "0102030405060708"
server-crt = "../../testdata/server.crt"
server-key = "../../testdata/server.key"`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot be combined with a certificate")
	})
}
