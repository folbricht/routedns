package rdns

import (
	"github.com/miekg/dns"
)

// DropResolver is a resolver that returns nil for every query which then
// causes any listeners to close the connection on the client.
type DropResolver struct {
	id string
}

var _ Resolver = &DropResolver{}

// NewDropResolver returns a new instance of a DropResolver resolver.
func NewDropResolver(id string) *DropResolver {
	return &DropResolver{id}
}

// Resolve a DNS query by returning nil to signal to the listener to drop this request.
func (r *DropResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	logger(r.id, q, ci).Debug("dropping query")
	return nil, nil
}

func (r *DropResolver) String() string {
	return r.id
}
