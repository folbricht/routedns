package rdns

import (
	"github.com/miekg/dns"
)

// TTLModifier passes queries to upstream resolvers and then modifies
// the TTL in response RRs according to limits.
type TTLModifier struct {
	id string
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
func NewTTLModifier(id string, resolver Resolver, opt TTLModifierOptions) *TTLModifier {
	return &TTLModifier{
		id:                 id,
		TTLModifierOptions: opt,
		resolver:           resolver,
	}
}

// Resolve a DNS query by first resoling it upstream, then applying TTL limits
// on the response.
func (r *TTLModifier) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	a, err := r.resolver.Resolve(q, ci)
	if err != nil || a == nil {
		return a, err
	}

	var modified bool
	for _, rrs := range [][]dns.RR{a.Answer, a.Ns, a.Extra} {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			h := rr.Header()
			if h.Ttl < r.MinTTL {
				h.Ttl = r.MinTTL
				modified = true
			}
			if r.MaxTTL > 0 && h.Ttl > r.MaxTTL {
				h.Ttl = r.MaxTTL
				modified = true
			}
		}
	}
	if modified {
		logger(r.id, q, ci).Debug("modified response ttl")
	}
	return a, nil
}

func (r *TTLModifier) String() string {
	return r.id
}
