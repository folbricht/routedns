package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Clients are counted per network, not per address, so the prefix decides who
// shares a limit with whom.
func TestRateLimiterPerNetwork(t *testing.T) {
	upstream := new(TestResolver)
	r := NewRateLimiter("test-rl", upstream, RateLimiterOptions{Requests: 2, Window: 3600})

	ask := func(ip string) bool {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		a, err := r.Resolve(q, ClientInfo{SourceIP: net.ParseIP(ip)})
		require.NoError(t, err)
		return a != nil // a dropped query answers with nothing
	}

	// Two addresses in the same /24 share the allowance of two.
	require.True(t, ask("192.168.1.1"))
	require.True(t, ask("192.168.1.2"))
	require.False(t, ask("192.168.1.3"), "the third query from a /24 is over the limit")

	// A different /24 has its own.
	require.True(t, ask("192.168.2.1"))

	// v6 is counted on its own prefix, 56 bits by default.
	require.True(t, ask("2001:db8:1:100::1"))
	require.True(t, ask("2001:db8:1:100::2"))
	require.False(t, ask("2001:db8:1:100::3"))
	require.True(t, ask("2001:db8:1:200::1"), "a different /56 has its own allowance")
}

// A query with no source address, which is what the components that make their
// own queries produce, must not bring the limiter down.
func TestRateLimiterNoSourceIP(t *testing.T) {
	r := NewRateLimiter("test-rl", new(TestResolver), RateLimiterOptions{Requests: 1, Window: 3600})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotNil(t, a)
}

// The prefix lengths are configurable, and what they change is who shares.
func TestRateLimiterPrefix(t *testing.T) {
	r := NewRateLimiter("test-rl", new(TestResolver), RateLimiterOptions{
		Requests: 1, Window: 3600, Prefix4: 32,
	})
	ask := func(ip string) bool {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		a, _ := r.Resolve(q, ClientInfo{SourceIP: net.ParseIP(ip)})
		return a != nil
	}
	require.True(t, ask("192.168.1.1"))
	require.False(t, ask("192.168.1.1"), "the same address twice is over a limit of one")
	require.True(t, ask("192.168.1.2"), "a /32 gives every address its own allowance")
}
