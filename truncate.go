package rdns

import (
        "github.com/miekg/dns"
)

// TruncateResolver is a resolver that always returns an answer with the Truncate (TC) bit set.
// This will tell the DNS client to "try again, but use TCP this time".
// Typically used in combination with the ratelimiter as simple DDOS mitigation
type TruncateResolver struct {
        id     string
}

var _ Resolver = &TruncateResolver{}

// NewTruncateResolver returns a new instance of a TruncateResolver resolver.
func NewTruncateResolver(id string) *TruncateResolver {
        return &TruncateResolver{id}
}

// Resolve a DNS query by returning a fixed response.
func (r *TruncateResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
        answer := new(dns.Msg)
        answer.SetReply(q)
        answer.Truncated = true // This is the bit!
        return answer, nil
}

func (r *TruncateResolver) String() string {
        return r.id
}
