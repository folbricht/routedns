package rdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type BlocklistMatcher interface {
	// Returns true if the question matches a record. If the IP is not nil,
	// respond with the given IP. NXDOMAIN otherwise.
	Match(q dns.Question) (net.IP, bool)

	fmt.Stringer
}
