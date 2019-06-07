package rdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// Resolver is an interface to resolve DNS queries.
type Resolver interface {
	Resolve(*dns.Msg) (*dns.Msg, error)
	fmt.Stringer
}
