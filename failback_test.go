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
	g1 := NewFailBack("test-fb", FailBackOptions{ResetAfter: time.Second}, failResolver, goodResolver)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	a, err := g1.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, a.Rcode)
	require.Equal(t, 0, goodResolver.hitCount)

	// With ServfailError == true
	g2 := NewFailBack("test-fb", FailBackOptions{ResetAfter: time.Second, ServfailError: true}, failResolver, goodResolver)

	a, err = g2.Resolve(q, ci)
	require.NoError(t, err)
	require.NotEqual(t, dns.RcodeServerFailure, a.Rcode)
	require.Equal(t, 1, goodResolver.hitCount)
}

func TestFailBackIsSuccessResponse(t *testing.T) {
	newFB := func(opts FailBackOptions) *FailBack {
		r := new(TestResolver)
		return NewFailBack("test-fb", opts, r)
	}

	newMsg := func(qtype uint16, rcode int) *dns.Msg {
		a := new(dns.Msg)
		a.SetQuestion("test.com.", qtype)
		a.Rcode = rcode
		return a
	}

	addAnswer := func(msg *dns.Msg, rrtype uint16) {
		switch rrtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			})
		case dns.TypeCNAME:
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "other.com.",
			})
		case dns.TypeHINFO:
			msg.Answer = append(msg.Answer, &dns.HINFO{
				Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 300},
			})
		case dns.TypeSOA:
			msg.Answer = append(msg.Answer, &dns.SOA{
				Hdr: dns.RR_Header{Name: "test.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			})
		}
	}

	addEDE := func(msg *dns.Msg, code uint16) {
		opt := msg.IsEdns0()
		if opt == nil {
			msg.SetEdns0(4096, false)
			opt = msg.IsEdns0()
		}
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code})
	}

	t.Run("NilResponse", func(t *testing.T) {
		fb := newFB(FailBackOptions{})
		require.True(t, fb.isSuccessResponse(nil))
	})

	t.Run("NilResponseWithEmptyError", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		require.True(t, fb.isSuccessResponse(nil))
	})

	t.Run("ServfailWithoutOption", func(t *testing.T) {
		fb := newFB(FailBackOptions{ServfailError: false})
		msg := newMsg(dns.TypeA, dns.RcodeServerFailure)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("ServfailWithOption", func(t *testing.T) {
		fb := newFB(FailBackOptions{ServfailError: true})
		msg := newMsg(dns.TypeA, dns.RcodeServerFailure)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("Refused", func(t *testing.T) {
		fb := newFB(FailBackOptions{})
		msg := newMsg(dns.TypeA, dns.RcodeRefused)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("NotImplemented", func(t *testing.T) {
		fb := newFB(FailBackOptions{})
		msg := newMsg(dns.TypeA, dns.RcodeNotImplemented)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("NXDomain", func(t *testing.T) {
		fb := newFB(FailBackOptions{})
		msg := newMsg(dns.TypeA, dns.RcodeNameError)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("NXDomainWithEmptyError", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeNameError)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyErrorDisabled", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: false})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("MatchingAnswerType", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeA)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("MatchingAnswerAfterCNAME", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeCNAME)
		addAnswer(msg, dns.TypeA)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("OnlyCNAMEsNoMatch", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeCNAME)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("CNAMEQueryWithCNAMEAnswer", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeCNAME, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeCNAME)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("OnlySOANoMatch", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeSOA)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyAnswerNoEDE", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyAnswerWithEDEBlocked", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addEDE(msg, dns.ExtendedErrorCodeBlocked)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyAnswerWithEDECensored", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addEDE(msg, dns.ExtendedErrorCodeCensored)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyAnswerWithEDEFiltered", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addEDE(msg, dns.ExtendedErrorCodeFiltered)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyAnswerWithOtherEDE", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addEDE(msg, dns.ExtendedErrorCodeOther)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyAnswerWithEDEProhibited", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addEDE(msg, dns.ExtendedErrorCodeProhibited)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("EmptyAnswerWithInvalidEDE", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeA, dns.RcodeSuccess)
		addEDE(msg, 9999)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("TypeANYWithHINFO", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeANY, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeHINFO)
		require.False(t, fb.isSuccessResponse(msg))
	})

	t.Run("TypeANYWithHINFOAndA", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeANY, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeHINFO)
		addAnswer(msg, dns.TypeA)
		require.True(t, fb.isSuccessResponse(msg))
	})

	t.Run("TypeANYWithRealAnswer", func(t *testing.T) {
		fb := newFB(FailBackOptions{EmptyError: true})
		msg := newMsg(dns.TypeANY, dns.RcodeSuccess)
		addAnswer(msg, dns.TypeA)
		require.True(t, fb.isSuccessResponse(msg))
	})
}
