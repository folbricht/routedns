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

	for i := 0; i < 10; i++ {
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
