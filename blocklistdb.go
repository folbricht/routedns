package rdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type BlocklistDB interface {
	// New initializes a new instance of the same database but with
	// the rules passed into it. Used to load new rules during an
	// ruleset refresh.
	New(rules []string) (BlocklistDB, error)

	// Returns true if the question matches a record. If the IP is not nil,
	// respond with the given IP. NXDOMAIN otherwise.
	Match(q dns.Question) (net.IP, bool)

	fmt.Stringer
}
