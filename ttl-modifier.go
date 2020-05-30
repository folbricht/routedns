package rdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// TTLModifier passes queries to upstream resolvers and then modifies
// the TTL in response RRs according to limits.
type TTLModifier struct {
	TTLModifierOptions
	resolver Resolver
}

var _ Resolver = &TTLModifier{}

type TTLModifierOptions struct {
	// Minimum TTL, any RR with a TTL below will be updated to this value.
	MinTTL uint32

	// Maximum TTL, any RR with a TTL higher than this will have their value
	// set to the max. A value of 0 disables the limit. Default 0.
	MaxTTL uint32
}

// NewTTLModifier returns a new instance of a TTL modifier.
func NewTTLModifier(resolver Resolver, opt TTLModifierOptions) *TTLModifier {
	return &TTLModifier{
		TTLModifierOptions: opt,
		resolver:           resolver,
	}
}

// Resolve a DNS query by first resoling it upstream, then applying TTL limits
// on the response.
func (r *TTLModifier) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	a, err := r.resolver.Resolve(q, ci)
	if err != nil {
		return a, err
	}

	for _, rrs := range [][]dns.RR{a.Answer, a.Ns, a.Extra} {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			h := rr.Header()
			if h.Ttl < r.MinTTL {
				h.Ttl = r.MinTTL
			}
			if r.MaxTTL > 0 && h.Ttl > r.MaxTTL {
				h.Ttl = r.MaxTTL
			}
		}
	}
	return a, nil
}

func (r *TTLModifier) String() string {
	return fmt.Sprintf("TTLModifier(%s)", r.resolver)
}
