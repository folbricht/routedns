package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestFailBack(t *testing.T) {
	// Build 2 resolvers that count the number of invocations
	var ci ClientInfo
	r1 := new(TestResolver)
	r2 := new(TestResolver)

	g := NewFailBack("test-fb", FailBackOptions{ResetAfter: time.Second}, r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Send the first couple of queries. The first resolver should be active and be used for both
	_, err := g.Resolve(q, ci)
	require.NoError(t, err)
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 2, r1.HitCount())
	require.Equal(t, 0, r2.HitCount())

	// Set the 1st to failure
	r1.SetFail(true)

	// The next one should hit both stores (1st will fail, 2nd succeed)
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 3, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())

	// Fix the 1st resolver and wait a second
	r1.SetFail(false)
	time.Sleep(time.Second + 100*time.Millisecond)

	// It should have been reset and the first should be active again now
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 5, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
}
