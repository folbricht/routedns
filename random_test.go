package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRandom(t *testing.T) {
	var ci ClientInfo
	r1 := new(TestResolver)
	r2 := new(TestResolver)

	g := NewRandom("test-random", RandomOptions{ResetAfter: time.Hour}, r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Successful queries are spread over both resolvers and don't count as failovers
	for i := 0; i < 10; i++ {
		_, err := g.Resolve(q, ci)
		require.NoError(t, err)
	}
	require.Equal(t, 10, r1.HitCount()+r2.HitCount())
	require.Equal(t, int64(0), g.metrics.failover.Value())
	require.Equal(t, int64(2), g.metrics.available.Value())

	// Break the first resolver. It gets deactivated on the first failure, which
	// is one failover, and every subsequent query goes to the second one.
	r1.SetFail(true)
	before := r2.HitCount()
	for i := 0; i < 10; i++ {
		_, err := g.Resolve(q, ci)
		require.NoError(t, err)
	}
	require.Equal(t, before+10, r2.HitCount())
	require.Equal(t, int64(1), g.metrics.failover.Value())
	require.Equal(t, int64(1), g.metrics.available.Value())

	// With both broken, the group runs out of resolvers and fails
	r2.SetFail(true)
	_, err := g.Resolve(q, ci)
	require.Error(t, err)
	require.Equal(t, int64(2), g.metrics.failover.Value())
	require.Equal(t, int64(0), g.metrics.available.Value())
}
