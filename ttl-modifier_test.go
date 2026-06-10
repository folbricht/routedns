package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Returns a resolver that responds with A records using the given TTLs, in order.
func ttlTestResolver(ttls ...uint32) *TestResolver {
	return &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			for i, ttl := range ttls {
				a.Answer = append(a.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					A: []byte{127, 0, 0, byte(i + 1)},
				})
			}
			return a, nil
		},
	}
}

func answerTTLs(a *dns.Msg) []uint32 {
	var ttls []uint32
	for _, rr := range a.Answer {
		ttls = append(ttls, rr.Header().Ttl)
	}
	return ttls
}

func TestTTLSelectFirst(t *testing.T) {
	r := NewTTLModifier("test-ttl", ttlTestResolver(300, 60, 600), TTLModifierOptions{
		SelectFunc: TTLSelectFirst,
	})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// All records must use the TTL of the first record
	require.Equal(t, []uint32{300, 300, 300}, answerTTLs(a))
}

func TestTTLSelectLast(t *testing.T) {
	r := NewTTLModifier("test-ttl", ttlTestResolver(300, 60, 600), TTLModifierOptions{
		SelectFunc: TTLSelectLast,
	})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// All records must use the TTL of the last record
	require.Equal(t, []uint32{600, 600, 600}, answerTTLs(a))
}

func TestTTLSelectLowest(t *testing.T) {
	r := NewTTLModifier("test-ttl", ttlTestResolver(300, 60, 600), TTLModifierOptions{
		SelectFunc: TTLSelectLowest,
	})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	require.Equal(t, []uint32{60, 60, 60}, answerTTLs(a))
}

func TestTTLSelectHighest(t *testing.T) {
	r := NewTTLModifier("test-ttl", ttlTestResolver(300, 60, 600), TTLModifierOptions{
		SelectFunc: TTLSelectHighest,
	})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	require.Equal(t, []uint32{600, 600, 600}, answerTTLs(a))
}
