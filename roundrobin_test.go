package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRoundRobin(t *testing.T) {
	// Build 2 resolvers that count the number of invocations
	r1 := new(TestResolver)
	r2 := new(TestResolver)

	g := NewRoundRobin("test-rr", r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Send 10 queries
	for i := 0; i < 10; i++ {
		_, err := g.Resolve(q, ClientInfo{})
		require.NoError(t, err)
	}

	// Each of the resolvers should have been used 5 times
	require.Equal(t, 5, r1.HitCount())
	require.Equal(t, 5, r2.HitCount())
}
