package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// check runs the config through --check.
func check(t *testing.T, content string) error {
	t.Helper()
	name := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(name, []byte(content), 0600))
	return run(options{check: true}, []string{name})
}

// Routers are the one part of the pipeline the test below doesn't build.
func TestCheckValidConfig(t *testing.T) {
	require.NoError(t, check(t, `
[resolvers.upstream]
address = "127.0.0.1:5399"
protocol = "udp"

[routers.router]
routes = [{type = "A", resolver = "upstream"}, {resolver = "upstream"}]

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
