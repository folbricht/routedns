package rdns

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// mustPack returns the wire form of a message, which is what the cache stores.
func mustPack(t *testing.T, m *dns.Msg) []byte {
	t.Helper()
	b, err := m.Pack()
	require.NoError(t, err)
	return b
}

// storedMsg decodes the message held by a cached item.
func storedMsg(t *testing.T, item *cacheItem) *dns.Msg {
	t.Helper()
	require.NotNil(t, item)
	m := new(dns.Msg)
	require.NoError(t, m.Unpack(item.blob.message()))
	return m
}

// store puts an answer in the cache the way memoryBackend.Store does.
func store(t *testing.T, c *lruCache, query *dns.Msg, answer *cacheAnswer) {
	t.Helper()
	key := lruKeyFromQuery(query)
	blob, err := newCacheBlob(key, answer)
	require.NoError(t, err)
	c.addKey(key, blob)
}

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
		store(t, c, msg, answer)
	}

	// Since the capacity is only 5 and we loaded 10, only the last 5 should be in there
	require.Equal(t, 5, c.size())

	// Check it's the right items in the cache
	for _, item := range items[:5] {
		require.Nil(t, c.get(item.query))
	}
	for _, item := range items[5:] {
		cached := c.get(item.query)
		require.NotNil(t, cached)
		require.Equal(t, mustPack(t, item.answer.Msg), cached.blob.message())
	}

	// Delete one of the items directly
	c.delete(items[5].query)
	require.Equal(t, 4, c.size())

	// Use an iterator to delete two more
	c.deleteFunc(func(item *cacheItem) bool {
		name := item.blob.key().Question.Name
		return name == "test8.com." || name == "test9.com."
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
	store(t, c, queryCD("cd.example.com.", true), cdAnswer)

	// A CD=0 lookup for the same name must NOT hit the CD=1 entry.
	require.Nil(t, c.get(queryCD("cd.example.com.", false)),
		"CD=0 query must not be served the cached CD=1 response")

	// The original CD=1 query still hits its own entry.
	require.Equal(t, mustPack(t, cdAnswer.Msg), c.get(queryCD("cd.example.com.", true)).blob.message())

	// Storing a CD=0 answer is kept separate from the CD=1 one.
	plainAnswer := answerFor("cd.example.com.")
	store(t, c, queryCD("cd.example.com.", false), plainAnswer)
	require.Equal(t, mustPack(t, plainAnswer.Msg), c.get(queryCD("cd.example.com.", false)).blob.message())
	require.Equal(t, mustPack(t, cdAnswer.Msg), c.get(queryCD("cd.example.com.", true)).blob.message())
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
	store(t, c, queryECS(24), answer24)

	// Same address, different prefix length must be a distinct entry.
	require.Nil(t, c.get(queryECS(16)),
		"ECS query with a different source-prefix length must not collide")
	require.NotNil(t, c.get(queryECS(24)))
}

// Two queries that the cache treats as different must not render the same key
// string, and two it treats as the same must render the same one.
func TestLRUKeyString(t *testing.T) {
	query := func(name string, qtype, qclass uint16, do, cd bool, subnet string, mask uint8) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, qtype)
		q.Question[0].Qclass = qclass
		q.CheckingDisabled = cd
		if do || subnet != "" {
			q.SetEdns0(4096, do)
			if subnet != "" {
				e := q.IsEdns0()
				s := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Address: net.ParseIP(subnet), SourceNetmask: mask}
				if s.Address.To4() != nil {
					s.Family = 1
				} else {
					s.Family = 2
				}
				e.Option = append(e.Option, s)
			}
		}
		return q
	}

	cases := map[string]*dns.Msg{
		"base":        query("example.com.", dns.TypeA, dns.ClassINET, false, false, "", 0),
		"other name":  query("example.org.", dns.TypeA, dns.ClassINET, false, false, "", 0),
		"other type":  query("example.com.", dns.TypeAAAA, dns.ClassINET, false, false, "", 0),
		"other class": query("example.com.", dns.TypeA, dns.ClassCHAOS, false, false, "", 0),
		"do":          query("example.com.", dns.TypeA, dns.ClassINET, true, false, "", 0),
		"cd":          query("example.com.", dns.TypeA, dns.ClassINET, false, true, "", 0),
		"subnet":      query("example.com.", dns.TypeA, dns.ClassINET, false, false, "192.0.2.0", 24),
		"subnet2":     query("example.com.", dns.TypeA, dns.ClassINET, false, false, "198.51.100.0", 24),
		"mask":        query("example.com.", dns.TypeA, dns.ClassINET, false, false, "192.0.2.0", 16),
		// A subnet and a name that could run into each other if the two were
		// simply concatenated.
		"run-on a":  query("com.", dns.TypeA, dns.ClassINET, false, false, "192.0.2.0", 24),
		"run-on b":  query("0.com.", dns.TypeA, dns.ClassINET, false, false, "192.0.2.", 24),
		"long name": query(strings.Repeat("a.", 100)+"com.", dns.TypeA, dns.ClassINET, false, false, "", 0),
	}

	seen := make(map[string]string, len(cases))
	for name, q := range cases {
		key := lruKeyFromQuery(q).string()
		if other, ok := seen[key]; ok {
			t.Errorf("%q and %q render the same key", name, other)
		}
		seen[key] = name
	}

	// The name is matched without regard to case, so the key must be too.
	upper := query("ExAmPlE.CoM.", dns.TypeA, dns.ClassINET, false, false, "", 0)
	require.Equal(t, lruKeyFromQuery(cases["base"]).string(), lruKeyFromQuery(upper).string())
}
