package rdns

import (
	"errors"

	"github.com/miekg/dns"
)

// EDNS0Modifier manipulates EDNS0 options, typically for codes in the 65001-65534 range.
type EDNS0Modifier struct {
	id       string
	resolver Resolver
	modifier EDNS0ModifierFunc
}

var _ Resolver = &EDNS0Modifier{}

// EDNS0ModifierFunc takes a DNS query and modifies its EDN0 records
type EDNS0ModifierFunc func(q *dns.Msg, ci ClientInfo)

// NewEDNS0Modifier initializes an EDNS0 modifier.
func NewEDNS0Modifier(id string, resolver Resolver, f EDNS0ModifierFunc) (*EDNS0Modifier, error) {
	c := &EDNS0Modifier{id: id, resolver: resolver, modifier: f}
	return c, nil
}

// Resolve modifies the OPT EDNS0 record and passes it to the next resolver.
func (r *EDNS0Modifier) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}

	// Modify the query
	if r.modifier != nil {
		r.modifier(q, ci)
	}

	// Pass it on upstream
	return r.resolver.Resolve(q, ci)
}

func (r *EDNS0Modifier) String() string {
	return r.id
}

func EDNS0ModifierDelete(code uint16) EDNS0ModifierFunc {
	return func(q *dns.Msg, ci ClientInfo) {
		edns0 := q.IsEdns0()
		if edns0 == nil {
			return
		}
		// Filter out any EDNS0 option with the same code
		newOpt := make([]dns.EDNS0, 0, len(edns0.Option))
		for _, opt := range edns0.Option {
			if opt.Option() == code {
				continue
			}
			newOpt = append(newOpt, opt)
		}
		edns0.Option = newOpt
	}
}

func EDNS0ModifierAdd(code uint16, data []byte) EDNS0ModifierFunc {
	return func(q *dns.Msg, ci ClientInfo) {
		// Drop any existing EDNS0 options with the same code
		EDNS0ModifierDelete(code)(q, ci)

		// Add a new record if there's no EDNS0 at all
		edns0 := q.IsEdns0()
		if edns0 == nil {
			q.SetEdns0(4096, false)
			edns0 = q.IsEdns0()
		}

		// Append the EDNS0 option
		opt := new(dns.EDNS0_LOCAL)
		opt.Code = code
		opt.Data = data
		edns0.Option = append(edns0.Option, opt)
	}
}
