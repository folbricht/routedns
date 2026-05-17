package rdns

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLRUAddGet(t *testing.T) {
	c := newLRUCache(5)

	type item struct {
		query  *dns.Msg
		answer *cacheAnswer
	}
	var items []item

	for i := range 10 {
		msg := new(dns.Msg)
		msg.SetQuestion(fmt.Sprintf("test%d.com.", i), dns.TypeA)
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(i),
				},
				A: net.IP{127, 0, 0, 1},
			},
		}
		answer := &cacheAnswer{Msg: msg}
		items = append(items, item{
			query:  msg,
			answer: answer,
		})
		// Load into the cache
		c.add(msg, answer)
	}

	// Since the capacity is only 5 and we loaded 10, only the last 5 should be in there
	require.Equal(t, 5, c.size())

	// Check it's the right items in the cache
	for _, item := range items[:5] {
		answer := c.get(item.query)
		require.Nil(t, answer)
	}
	for _, item := range items[5:] {
		answer := c.get(item.query)
		require.NotNil(t, answer)
		require.Equal(t, item.answer, answer)
	}

	// Delete one of the items directly
	c.delete(items[5].query)
	require.Equal(t, 4, c.size())

	// Use an iterator to delete two more
	c.deleteFunc(func(a *cacheAnswer) bool {
		question := a.Msg.Question[0]
		return question.Name == "test8.com." || question.Name == "test9.com."
	})
	require.Equal(t, 2, c.size())
}

// A CD=1 response is unvalidated (RFC 4035 §4.7 / RFC 6840 §5.9) and must not
// be served to a CD=0 client. The cache key must therefore distinguish them.
func TestLRUKeyCD(t *testing.T) {
	answerFor := func(name string) *cacheAnswer {
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeA)
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IP{127, 0, 0, 1},
			},
		}
		return &cacheAnswer{Msg: msg}
	}

	queryCD := func(name string, cd bool) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		q.CheckingDisabled = cd
		return q
	}

	c := newLRUCache(10)

	// Store an (unvalidated) answer for a CD=1 query.
	cdAnswer := answerFor("cd.example.com.")
	c.add(queryCD("cd.example.com.", true), cdAnswer)

	// A CD=0 lookup for the same name must NOT hit the CD=1 entry.
	require.Nil(t, c.get(queryCD("cd.example.com.", false)),
		"CD=0 query must not be served the cached CD=1 response")

	// The original CD=1 query still hits its own entry.
	require.Equal(t, cdAnswer, c.get(queryCD("cd.example.com.", true)))

	// Storing a CD=0 answer is kept separate from the CD=1 one.
	plainAnswer := answerFor("cd.example.com.")
	c.add(queryCD("cd.example.com.", false), plainAnswer)
	require.Equal(t, plainAnswer, c.get(queryCD("cd.example.com.", false)))
	require.Equal(t, cdAnswer, c.get(queryCD("cd.example.com.", true)))
	require.Equal(t, 2, c.size())
}

// ECS responses with a different source-prefix length have a different scope
// and must not collide on the cache key.
func TestLRUKeyECSMask(t *testing.T) {
	queryECS := func(mask uint8) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("ecs.example.com.", dns.TypeA)
		q.SetEdns0(4096, false)
		ecs := new(dns.EDNS0_SUBNET)
		ecs.Code = dns.EDNS0SUBNET
		ecs.Family = 1
		ecs.SourceNetmask = mask
		ecs.SourceScope = 0
		ecs.Address = net.IP{192, 0, 2, 0}
		q.IsEdns0().Option = append(q.IsEdns0().Option, ecs)
		return q
	}

	c := newLRUCache(10)

	answer24 := &cacheAnswer{Msg: new(dns.Msg)}
	c.add(queryECS(24), answer24)

	// Same address, different prefix length must be a distinct entry.
	require.Nil(t, c.get(queryECS(16)),
		"ECS query with a different source-prefix length must not collide")
	require.NotNil(t, c.get(queryECS(24)))
}
