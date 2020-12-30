package rdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type BlocklistDB interface {
	// Reload initializes a new instance of the same database but with
	// a new ruleset loaded.
	Reload() (BlocklistDB, error)

	// Returns true if the question matches a rule. If the IP is not nil,
	// respond with the given IP. NXDOMAIN otherwise.
	Match(q dns.Question) (net.IP, string, string, bool)

	fmt.Stringer
}
