package rdns

import (
	"math"
	"math/rand"

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

type TTLSelectFunc func(*TTLModifier, *dns.Msg) bool

type TTLModifierOptions struct {
	// Function performing the initial modifications (min/max are applied after).
	// Returns true if at least one value was modified.
	SelectFunc TTLSelectFunc

	// Minimum TTL, any RR with a TTL below will be updated to this value.
	MinTTL uint32

	// Maximum TTL, any RR with a TTL higher than this will have their value
	// set to the max. A value of 0 disables the limit. Default 0.
	MaxTTL uint32
}

// NewTTLModifier returns a new instance of a TTL modifier.
func NewTTLModifier(id string, resolver Resolver, opt TTLModifierOptions) *TTLModifier {
	if opt.MaxTTL == 0 {
		opt.MaxTTL = math.MaxUint32
	}
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

	// Run the modifier function if any
	var modified bool
	if r.SelectFunc != nil {
		modified = r.SelectFunc(r, a)
	}

	// Apply min/max to the results
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl < r.MinTTL {
			h.Ttl = r.MinTTL
			modified = true
		}
		if h.Ttl > r.MaxTTL {
			h.Ttl = r.MaxTTL
			modified = true
		}
	})
	if modified {
		logger(r.id, q, ci).Debug("modified response ttl")
	}
	return a, nil
}

func (r *TTLModifier) String() string {
	return r.id
}

// TTLSelectLowest is a function for the TTL Modifier that sets the TTL
// to the lowest value of all records.
func TTLSelectLowest(r *TTLModifier, a *dns.Msg) bool {
	var modified bool
	var lowest uint32 = math.MaxUint32
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl < lowest {
			lowest = h.Ttl
		}
	})
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl != lowest {
			modified = true
		}
		h.Ttl = lowest
	})
	return modified
}

// TTLSelectHighest is a function for the TTL Modifier that sets the TTL
// to the highest value of all records.
func TTLSelectHighest(r *TTLModifier, a *dns.Msg) bool {
	var modified bool
	var highest uint32 = 0
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl > highest {
			highest = h.Ttl
		}
	})
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl != highest {
			modified = true
		}
		h.Ttl = highest
	})
	return modified
}

// TTLSelectAverage is a function for the TTL Modifier that sets the TTL
// to the average value of all records.
func TTLSelectAverage(r *TTLModifier, a *dns.Msg) bool {
	var (
		modified bool
		sum, n   int
	)
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		n++
		sum += int(h.Ttl)
	})
	if n == 0 {
		// Avoid division by 0 for empty responses
		n = 1
	}
	average := uint32(sum / n)
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl != average {
			modified = true
		}
		h.Ttl = average
	})
	return modified
}

// TTLSelectFirst is a function for the TTL Modifier that sets the TTL
// to the value of the first record.
func TTLSelectFirst(r *TTLModifier, a *dns.Msg) bool {
	var (
		modified bool
		first    uint32
		gotFirst bool
	)
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if gotFirst {
			return
		}
		first = h.Ttl
	})
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl != first {
			modified = true
		}
		h.Ttl = first
	})
	return modified
}

// TTLSelectLast is a function for the TTL Modifier that sets the TTL
// to the value of the last record.
func TTLSelectLast(r *TTLModifier, a *dns.Msg) bool {
	var (
		modified bool
		last     uint32
	)
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		last = h.Ttl
	})
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		if h.Ttl != last {
			modified = true
		}
		h.Ttl = last
	})
	return modified
}

// TTLSelectRandom is a function for the TTL Modifier that sets the TTL
// to a random value between ttl-min and ttl-max.
func TTLSelectRandom(r *TTLModifier, a *dns.Msg) bool {
	value := r.MinTTL + uint32(rand.Intn(int(r.MaxTTL-r.MinTTL)))
	iterateOverAnswerRRHeader(a, func(h *dns.RR_Header) {
		h.Ttl = value
	})
	return true
}

func iterateOverAnswerRRHeader(a *dns.Msg, f func(*dns.RR_Header)) {
	for _, rrs := range [][]dns.RR{a.Answer, a.Ns, a.Extra} {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			h := rr.Header()
			f(h)
		}
	}
}
