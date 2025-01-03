package rdns

import (
	"github.com/miekg/dns"
)

// ResponseCollapse is a resolver that collapses response records to just the type
// of the query, eliminating answer chains.
type ResponseCollapse struct {
	id       string
	resolver Resolver
	ResponseCollapseOptions
}

type ResponseCollapseOptions struct {
	NullRCode int // Response code when there's nothing left after collapsing the response
}

var _ Resolver = &ResponseCollapse{}

// NewResponseMinimize returns a new instance of a response minimizer.
func NewResponseCollapse(id string, resolver Resolver, opt ResponseCollapseOptions) *ResponseCollapse {
	return &ResponseCollapse{id: id, resolver: resolver, ResponseCollapseOptions: opt}
}

// Resolve a DNS query, then collapse the response to remove anything from the
// answer that wasn't asked for.
func (r *ResponseCollapse) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil || answer.Rcode != dns.RcodeSuccess {
		return answer, err
	}
	name := q.Question[0].Name
	qType := q.Question[0].Qtype
	qClass := q.Question[0].Qclass
	var aRR []dns.RR
	for _, rr := range answer.Answer {
		h := rr.Header()
		if h.Rrtype == qType && h.Class == qClass {
			h.Name = name
			aRR = append(aRR, rr)
		}
	}
	answer.Answer = aRR
	log := logger(r.id, q, ci)

	// If there's nothing left after collapsing, return the null response code
	if len(answer.Answer) == 0 {
		log.Debug("no answer left after collapse, returning",
			"response code", r.NullRCode)
		return responseWithCode(q, r.NullRCode), nil
	}
	log.Debug("collapsing response")
	return answer, nil
}

func (r *ResponseCollapse) String() string {
	return r.id
}
