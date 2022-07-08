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

func TestFailBackSERVFAIL(t *testing.T) {
	// Build 2 resolvers that count the number of invocations
	var ci ClientInfo
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	r1, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)

	r2 := new(TestResolver)

	g := NewFailBack("test-fb", FailBackOptions{ResetAfter: time.Second, ServfailError: true}, r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Send the first query, the first resolver will return SERVFAIL and the request will go to the 2nd
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r2.HitCount())
}

func TestFailBackDrop(t *testing.T) {
	var ci ClientInfo
	r1 := NewDropResolver("test-drop")
	r2 := new(TestResolver)

	g := NewFailBack("test-fb", FailBackOptions{ResetAfter: time.Second}, r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// The query should be dropped, so no failover
	_, err := g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 0, r2.HitCount())
}

// Return SERVFAIL if all available resolvers return that
func TestFailBackSERVFAILAll(t *testing.T) {
	var ci ClientInfo
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	r, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)

	g := NewFailBack("test-fb", FailBackOptions{ResetAfter: time.Second}, r, r)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	a, err := g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, a.Rcode)
}

// Make sure that the ServfailError option triggers a failover
func TestFailBackServfailOKOption(t *testing.T) {
	var ci ClientInfo
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	failResolver, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)
	goodResolver := new(TestResolver)

	// With ServfailError == false
	g1 := NewFailBack("test-fb", FailBackOptions{}, failResolver, goodResolver)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	a, err := g1.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, a.Rcode)
	require.Equal(t, 0, goodResolver.hitCount)

	// With ServfailError == true
	g2 := NewFailBack("test-fb", FailBackOptions{ServfailError: true}, failResolver, goodResolver)

	a, err = g2.Resolve(q, ci)
	require.NoError(t, err)
	require.NotEqual(t, dns.RcodeServerFailure, a.Rcode)
	require.Equal(t, 1, goodResolver.hitCount)
}
