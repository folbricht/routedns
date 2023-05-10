package rdns

import (
	"github.com/miekg/dns"
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

// Resolve a DNS query with the upstream resolver and strip out any extra or NS
// records in the response.
func (r *ResponseMinimize) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil {
		return answer, err
	}
	logger(r.id, q, ci).Debug("stripping response")
	answer.Extra = nil
	answer.Ns = nil
	return answer, nil
}

func (r *ResponseMinimize) String() string {
	return r.id
}
