package rdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// Resolver is an interface to resolve DNS queries.
type Resolver interface {
	Resolve(*dns.Msg, ClientInfo) (*dns.Msg, error)
	fmt.Stringer
}

// isSuccessResponse returns true if the response should be considered a
// successful result given the provided options. A nil response is treated as
// empty and handled according to emptyError.
func isSuccessResponse(a *dns.Msg, servfailError, emptyError bool) bool {
	if a == nil {
		return !emptyError
	}
	if (a.Rcode == dns.RcodeServerFailure && servfailError) ||
		a.Rcode == dns.RcodeRefused ||
		a.Rcode == dns.RcodeNotImplemented {
		return false
	}
	if !emptyError {
		return true
	}
	if len(a.Answer) > 0 && len(a.Question) > 0 {
		// Check if the reply has useful records (SOA is not useful)
		for _, rr := range a.Answer {
			if rr.Header().Rrtype == a.Question[0].Qtype {
				return true
			}
		}
		if a.Question[0].Qtype == dns.TypeANY {
			return !(len(a.Answer) == 1 && a.Answer[0].Header().Rrtype == dns.TypeHINFO)
		}
	} else {
		// Check if the reply was deliberately empty
		if edns0 := a.IsEdns0(); edns0 != nil {
			for _, opt := range edns0.Option {
				if ede, ok := opt.(*dns.EDNS0_EDE); ok {
					switch ede.InfoCode {
					case dns.ExtendedErrorCodeBlocked, dns.ExtendedErrorCodeCensored, dns.ExtendedErrorCodeFiltered:
						return true
					}
				}
			}
		}
	}
	return false
}
