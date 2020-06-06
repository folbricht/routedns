package rdns

import (
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// RoundRobin is a group of recolvers that will receive equal amounts of queries.
// Failed queries are not retried.
type RoundRobin struct {
	id        string
	resolvers []Resolver
	mu        sync.Mutex
	current   int
}

var _ Resolver = &RoundRobin{}

// NewRoundRobin returns a new instance of a round-robin resolver group.
func NewRoundRobin(id string, resolvers ...Resolver) *RoundRobin {
	return &RoundRobin{id: id, resolvers: resolvers}
}

// Resolve a DNS query using a round-robin resolver group.
func (r *RoundRobin) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	r.mu.Lock()
	resolver := r.resolvers[r.current]
	r.current = (r.current + 1) % len(r.resolvers)
	r.mu.Unlock()
	Log.WithFields(logrus.Fields{
		"id":       r.id,
		"client":   ci.SourceIP,
		"qname":    qName(q),
		"resolver": resolver.String(),
	}).Debug("forwarding query to resolver")
	return resolver.Resolve(q, ci)
}

func (r *RoundRobin) String() string {
	return r.id
}
