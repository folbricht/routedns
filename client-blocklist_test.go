package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A query without a client IP (internal DNSSEC/prefetch lookups, anonymous
// ODoH) must not crash a CIDR client-blocklist that contains an IPv6 prefix.
// See: nil SourceIP previously panicked in the IPv6 trie.
func TestClientBlocklistNilSourceIP(t *testing.T) {
	loader := NewStaticLoader([]string{
		"127.0.0.0/24",
		"2a03:2880:f101:83::0/64",
	})
	db, err := NewCidrDB("testlist", loader)
	require.NoError(t, err)

	r := &TestResolver{}
	b, err := NewClientBlocklist("test-cb", r, ClientBlocklistOptions{BlocklistDB: db})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// ClientInfo{} has a nil SourceIP. This must pass through to the
	// inner resolver instead of panicking.
	a, err := b.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotNil(t, a)
	require.Equal(t, 1, r.HitCount())
}

// A query carrying a blocked client IP is still refused (normal behavior
// unchanged by the nil guard).
func TestClientBlocklistMatch(t *testing.T) {
	loader := NewStaticLoader([]string{
		"192.168.0.0/16",
		"2a03:2880:f101:83::0/64",
	})
	db, err := NewCidrDB("testlist", loader)
	require.NoError(t, err)

	r := &TestResolver{}
	b, err := NewClientBlocklist("test-cb", r, ClientBlocklistOptions{BlocklistDB: db})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Blocked client -> REFUSED, inner resolver not called.
	a, err := b.Resolve(q, ClientInfo{SourceIP: net.ParseIP("192.168.1.1")})
	require.NoError(t, err)
	require.Equal(t, dns.RcodeRefused, a.Rcode)
	require.Equal(t, 0, r.HitCount())

	// Allowed client -> passed through.
	a, err = b.Resolve(q, ClientInfo{SourceIP: net.ParseIP("10.0.0.1")})
	require.NoError(t, err)
	require.NotNil(t, a)
	require.Equal(t, 1, r.HitCount())
}
