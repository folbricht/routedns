package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestFailRotate(t *testing.T) {
	// Build 2 resolvers that count the number of invocations
	var ci ClientInfo
	r1 := new(TestResolver)
	r2 := new(TestResolver)

	g := NewFailRotate("test-rotate", FailRotateOptions{}, r1, r2)
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

	// Fix the 1st resolver
	r1.SetFail(false)

	// Any further requests should only go to the 2nd
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 3, r1.HitCount())
	require.Equal(t, 3, r2.HitCount())

	// Break the 2nd
	r2.SetFail(true)

	// This request should go to the 2nd and then be retried on the first
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 4, r1.HitCount())
	require.Equal(t, 4, r2.HitCount())

	// Break both, requests should all fail now after trying both
	r1.SetFail(true)
	_, err = g.Resolve(q, ci)
	require.Error(t, err)
	require.Equal(t, 5, r1.HitCount())
	require.Equal(t, 5, r2.HitCount())
}

func TestFailRotateSERVFAIL(t *testing.T) {
	var ci ClientInfo
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	r1, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)

	r2 := new(TestResolver)

	g := NewFailRotate("test-rotate", FailRotateOptions{ServfailError: true}, r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Send the first query, the first resolver will return SERVFAIL and the request will go to the 2nd
	_, err = g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r2.HitCount())
}

func TestFailRotateDrop(t *testing.T) {
	var ci ClientInfo
	r1 := NewDropResolver("test-drop")
	r2 := new(TestResolver)

	g := NewFailRotate("test-rotate", FailRotateOptions{}, r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// The query should be dropped, so no failover
	_, err := g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 0, r2.HitCount())
}

// Return SERVFAIL if all available resolvers return that
func TestFailRotateSERVFAILAll(t *testing.T) {
	var ci ClientInfo
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	r, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)

	g := NewFailRotate("test-rotate", FailRotateOptions{}, r, r)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	a, err := g.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, a.Rcode)
}
