package rdns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	var ci ClientInfo
	q := new(dns.Msg)
	answerTTL := uint32(3600)
	r := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			a.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    answerTTL,
					},
					A: net.IP{127, 0, 0, 1},
				},
			}
			return a, nil
		},
	}

	opt := CacheOptions{
		GCPeriod: time.Minute,
	}
	c := NewCache("test-cache", r, opt)

	// First query should be a cache-miss and be passed on to the upstream resolver
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
	require.Equal(t, uint32(3600), a.Answer[0].Header().Ttl)

	time.Sleep(time.Second)

	// Second one should come from the cache and should have a lower TTL
	a, err = c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
	require.True(t, a.Answer[0].Header().Ttl < answerTTL)

	// Different question should go through to upstream again, low TTL
	answerTTL = 1
	q.SetQuestion("example2.com.", dns.TypeA)
	a, err = c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 2, r.HitCount())
	require.Equal(t, answerTTL, a.Answer[0].Header().Ttl)

	time.Sleep(time.Second)

	// TTL should have expired now, so this should be a cache-miss and be sent upstream
	q.SetQuestion("example2.com.", dns.TypeA)
	_, err = c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 3, r.HitCount())
}

func TestCacheNXDOMAIN(t *testing.T) {
	var ci ClientInfo
	q := new(dns.Msg)
	r := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			a.SetRcode(q, dns.RcodeNameError)
			return a, nil
		},
	}

	opt := CacheOptions{
		GCPeriod: time.Minute,
	}
	c := NewCache("test-cache", r, opt)

	// First query should be a cache-miss and be passed on to the upstream resolver
	// Since it's an NXDOMAIN it should end up in the cache as well, with default TTL
	q.SetQuestion("example.com.", dns.TypeA)
	_, err := c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())

	// Second one should be returned from the cache
	_, err = c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
}

func TestCacheHardenBelowNXDOMAIN(t *testing.T) {
	var ci ClientInfo
	q := new(dns.Msg)
	r := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			a.SetRcode(q, dns.RcodeNameError)
			return a, nil
		},
	}

	opt := CacheOptions{
		GCPeriod:            time.Minute,
		HardenBelowNXDOMAIN: true,
	}
	c := NewCache("test-cache", r, opt)

	// Cache an NXDOMAIN for the parent domain
	q.SetQuestion("example.com.", dns.TypeA)
	_, err := c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())

	// A sub-domain query should also return NXDOMAIN based on the cached
	// record for the parent if HardenBelowNXDOMAIN is enabled.
	q.SetQuestion("not.exist.example.com.", dns.TypeA)
	a, err := c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
	require.Equal(t, dns.RcodeNameError, a.Rcode)
}

func TestRoundRobinShuffle(t *testing.T) {
	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   "test",
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
				},
				Target: "test",
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "test",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: net.IP{0, 0, 0, 1},
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "test",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: net.IP{0, 0, 0, 2},
			},
		},
	}
	// Shift the A records
	AnswerShuffleRoundRobin(msg)

	require.Equal(t, dns.TypeCNAME, msg.Answer[0].Header().Rrtype)
	require.Equal(t, dns.TypeA, msg.Answer[1].Header().Rrtype)
	require.Equal(t, dns.TypeA, msg.Answer[2].Header().Rrtype)

	a1 := msg.Answer[1].(*dns.A)
	a2 := msg.Answer[2].(*dns.A)
	require.Equal(t, net.IP{0, 0, 0, 2}, a1.A)
	require.Equal(t, net.IP{0, 0, 0, 1}, a2.A)
}

// Truncated responses should not be cached
func TestCacheNoTruncated(t *testing.T) {
	var ci ClientInfo
	q := new(dns.Msg)
	r := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			a.Truncated = true
			return a, nil
		},
	}

	c := NewCache("test-cache", r, CacheOptions{})

	// Both queries should hit the upstream resolver
	q.SetQuestion("example.com.", dns.TypeA)
	_, err := c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
	_, err = c.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 2, r.HitCount())
}
