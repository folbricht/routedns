package rdns

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestFastest(t *testing.T) {
	// Build 2 resolvers that count the number of invocations
	var ci ClientInfo
	r1 := &TestResolver{ // slow resolver, with one A record in the response
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			time.Sleep(10 * time.Millisecond)
			a := new(dns.Msg)
			a.SetReply(q)
			a.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IP{127, 0, 0, 1},
				},
			}
			return a, nil

		},
	}
	r2 := new(TestResolver) // fast resolver

	g := NewFastest("fastest", r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Send the first query, it should go to both and the fast response (with A record) should come back.
	a, err := g.Resolve(q, ci)
	require.NoError(t, err)

	time.Sleep(time.Millisecond) // Wait to make sure both resolvers are actually hit before checking the hit-count

	require.Equal(t, 1, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
	require.Equal(t, 0, len(a.Answer))
}

func TestFastestFail(t *testing.T) {
	var ci ClientInfo

	// Fast resolver that fails
	opt := StaticResolverOptions{
		RCode: dns.RcodeServerFailure,
	}
	r1, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)

	// Slow resolver that succeeds
	r2 := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			time.Sleep(10 * time.Millisecond)
			a := new(dns.Msg)
			a.SetReply(q)
			a.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IP{127, 0, 0, 1},
				},
			}
			return a, nil

		},
	}

	g := NewFastest("fastest", r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// We have a fast failing, and a slow succeeding one. Expect success
	a, err := g.Resolve(q, ci)
	require.NoError(t, err)

	require.Equal(t, 1, r2.HitCount())
	require.Equal(t, 1, len(a.Answer))

}
func TestFastestFailAll(t *testing.T) {
	var ci ClientInfo

	// Fast resolver that fails with an error
	r1 := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return nil, errors.New("failed")
		},
	}

	// Slow resolver that fails with SERVFAIL
	r2 := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			time.Sleep(10 * time.Millisecond)
			a := new(dns.Msg)
			a.SetRcode(q, dns.RcodeServerFailure)
			return a, nil
		},
	}

	g := NewFastest("fastest", r1, r2)
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	// Expect the response to be from the slow SERVFAIL
	a, err := g.Resolve(q, ci)
	require.NoError(t, err)

	require.Equal(t, 1, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
	require.Equal(t, dns.RcodeServerFailure, a.Rcode)
}
