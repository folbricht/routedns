package rdns

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ResponseCollapse is a resolver that collapses response records to just the type
// of the query, eliminating answer chains.
type ResponseCollapse struct {
	id       string
	resolver Resolver
}

var _ Resolver = &ResponseCollapse{}

// NewResponseMinimize returns a new instance of a response minimizer.
func NewResponseCollapse(id string, resolver Resolver) *ResponseCollapse {
	return &ResponseCollapse{id: id, resolver: resolver}
}

// Resolve a DNS query using a random resolver.
func (r *ResponseCollapse) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil {
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
	log := Log.WithFields(logrus.Fields{"id": r.id, "client": ci.SourceIP, "qname": name})

	// If there's nothing left after collapsing, return NXDOMAIN
	if len(answer.Answer) == 0 {
		log.Debug("no answer left after collapse, returning nxdomain")
		return nxdomain(q), nil
	}
	log.Debug("collapsing response")
	return answer, nil
}

func (r *ResponseCollapse) String() string {
	return r.id
}
