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
	// respond with the given IP. NXDOMAIN otherwise. The returned names,
	// if set, are used to answer PTR queries
	Match(msg *dns.Msg) (ip []net.IP, names []string, m *BlocklistMatch, matched bool)

	fmt.Stringer
}

// BlocklistMatch is returned by blocklists when a match is found. It contains
// information about what rule matched, what list it was from etc. Used mostly
// for logging.
type BlocklistMatch struct {
	List string // Identifier or name of the blocklist
	Rule string // Identifier for the rule that matched
}

func (m *BlocklistMatch) GetList() string {
	if m == nil {
		return "none"
	}
	return m.List
}

func (m *BlocklistMatch) GetRule() string {
	if m == nil {
		return "none"
	}
	return m.Rule
}
