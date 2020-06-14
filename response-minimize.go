package rdns

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ResponseMinimize is a resolver that strips Extra and Authority records
// from responses, leaving just the answer records.
type ResponseMinimize struct {
	id       string
	resolver Resolver
}

var _ Resolver = &ResponseMinimize{}

// NewResponseMinimize returns a new instance of a response minimizer.
func NewResponseMinimize(id string, resolver Resolver) *ResponseMinimize {
	return &ResponseMinimize{id: id, resolver: resolver}
}

// Resolve a DNS query using a random resolver.
func (r *ResponseMinimize) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil {
		return answer, err
	}
	Log.WithFields(logrus.Fields{"id": r.id, "client": ci.SourceIP, "qname": qName(q)}).Debug("stripping response")
	answer.Extra = nil
	answer.Ns = nil
	return answer, nil
}

func (r *ResponseMinimize) String() string {
	return r.id
}
