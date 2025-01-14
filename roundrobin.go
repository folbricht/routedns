package rdns

import (
	"sync"

	"github.com/miekg/dns"
)

// RoundRobin is a group of resolvers that will receive equal amounts of queries.
// Failed queries are not retried.
type RoundRobin struct {
	id        string
	resolvers []Resolver
	mu        sync.Mutex
	current   int
	metrics   *RouterMetrics
}

var _ Resolver = &RoundRobin{}

// NewRoundRobin returns a new instance of a round-robin resolver group.
func NewRoundRobin(id string, resolvers ...Resolver) *RoundRobin {
	return &RoundRobin{
		id:        id,
		resolvers: resolvers,
		metrics:   NewRouterMetrics(id, len(resolvers)),
	}
}

// Resolve a DNS query using a round-robin resolver group.
func (r *RoundRobin) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	r.mu.Lock()
	resolver := r.resolvers[r.current]
	r.current = (r.current + 1) % len(r.resolvers)
	r.mu.Unlock()
	logger(r.id, q, ci).With("resolver", resolver).Debug("forwarding query to resolver")
	r.metrics.route.Add(resolver.String(), 1)
	msg, err := resolver.Resolve(q, ci)
	if err != nil {
		r.metrics.failure.Add(resolver.String(), 1)
	}
	return msg, err
}

func (r *RoundRobin) String() string {
	return r.id
}
