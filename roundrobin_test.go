package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRoundRobin(t *testing.T) {
	// Build 2 resolvers that count the number of invocations
	var c1, c2 int
	r1 := TestResolver(func(q *dns.Msg) (*dns.Msg, error) {
		c1++
		return q, nil
	})
	r2 := TestResolver(func(q *dns.Msg) (*dns.Msg, error) {
		c2++
		return q, nil
	})

	g := NewRoundRobin(r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Send 10 queries
	for i := 0; i < 10; i++ {
		_, err := g.Resolve(q)
		require.NoError(t, err)
	}

	// Each of the resolvers should have been used 5 times
	require.Equal(t, 5, c1)
	require.Equal(t, 5, c2)
}
