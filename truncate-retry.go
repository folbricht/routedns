package rdns

import (
	"github.com/miekg/dns"
)

// TruncateRetry retries truncated responses with an alternative resolver. This
// is typically used when using UDP/DTLS transports, to fail over to a stream-
// based protocol.
type TruncateRetry struct {
	id string
	TruncateRetryOptions
	resolver      Resolver
	retryResolver Resolver
}

var _ Resolver = &TruncateRetry{}

type TruncateRetryOptions struct {
}

// NewTruncateRetry returns a new instance of a truncate-retry router.
func NewTruncateRetry(id string, resolver, retryResolver Resolver, opt TruncateRetryOptions) *TruncateRetry {
	return &TruncateRetry{
		id:                   id,
		TruncateRetryOptions: opt,
		retryResolver:        retryResolver,
		resolver:             resolver,
	}
}

// Resolve a DNS query by first resoling it upstream, if the response is truncated, the
// retry resolver is used to resolve the same query again.
func (r *TruncateRetry) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	a, err := r.resolver.Resolve(q, ci)
	if err != nil || a == nil {
		return a, err
	}

	// Retry the same query on the other resolver if the first one returned a truncated response.
	if a.Truncated {
		logger(r.id, q, ci).With("resolver", r.retryResolver).Debug("truncated response, forwarding to retry-resolver")
		a, err = r.retryResolver.Resolve(q, ci)
	}
	return a, err
}

func (r *TruncateRetry) String() string {
	return r.id
}
