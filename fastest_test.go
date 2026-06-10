package rdns

import (
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestFastest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		// Let the (virtual) clock run past the slow resolver's sleep so its
		// goroutine completes and exits before the bubble ends, then wait for
		// it to settle before checking the hit-count.
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()

		require.Equal(t, 1, r1.HitCount())
		require.Equal(t, 1, r2.HitCount())
		require.Equal(t, 0, len(a.Answer))
	})
}

func TestFastestFail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

func TestFastestFailAll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// Each resolver branch must receive its own copy of the query. Modifiers
// in the branches change the message in place, which races between the
// concurrent branches if the message is shared. Run with -race.
func TestFastestQueryNotShared(t *testing.T) {
	mutator := func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		// Mutate the query like ecs-modifier or edns0-modifier would
		q.SetEdns0(4096, false)
		a := new(dns.Msg)
		a.SetReply(q)
		return a, nil
	}
	r1 := &TestResolver{ResolveFunc: mutator}
	r2 := &TestResolver{ResolveFunc: mutator}

	g := NewFastest("fastest", r1, r2)
	for range 100 {
		q := new(dns.Msg)
		q.SetQuestion("test.com.", dns.TypeA)
		a, err := g.Resolve(q, ClientInfo{})
		require.NoError(t, err)
		require.NotNil(t, a)
		// The caller's query must not have been modified by the branches
		require.Nil(t, q.IsEdns0())
	}
}
