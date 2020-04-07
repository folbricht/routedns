package rdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DomainDB holds a list of domain strings (potentially with wildcards). Matching
// logic:
// domain.com: matches just domain.com and not subdomains
// .domain.com: matches domain.com and all subdomains
// *.domain.com: matches all subdomains but not domain.com
type DomainDB struct {
	root node
}

type node map[string]node

var _ BlocklistDB = &DomainDB{}

// NewDomainDB returns a new instance of a matcher for a list of regular expressions.
func NewDomainDB(rules ...string) (*DomainDB, error) {
	root := make(node)
	for _, r := range rules {
		// Strip trailing . in case the list has FQDN names with . suffixes.
		r = strings.TrimSuffix(r, ".")

		// Break up the domain into its parts and iterare backwards over them, building
		// a graph of maps
		parts := strings.Split(r, ".")
		n := root
		for i := len(parts) - 1; i >= 0; i-- {
			part := parts[i]

			// Only allow wildcards as the first domain part, and not in a string
			if strings.Contains(part, "*") && (i > 0 || len(part) != 1) {
				return nil, fmt.Errorf("invalid blocklist item: '%s'", part)
			}

			subNode, ok := n[part]
			if !ok {
				subNode = make(node)
				n[part] = subNode
			}
			n = subNode
		}
	}
	return &DomainDB{root: root}, nil
}

func (m *DomainDB) New(rules []string) (BlocklistDB, error) {
	return NewDomainDB(rules...)
}

func (m *DomainDB) Match(q dns.Question) (net.IP, bool) {
	s := strings.TrimSuffix(q.Name, ".")
	parts := strings.Split(s, ".")
	n := m.root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		subNode, ok := n[part]
		if !ok {
			return nil, false
		}
		if _, ok := subNode[""]; ok { // exact and sub-domain match
			return nil, true
		}
		if _, ok := subNode["*"]; ok && i > 0 { // wildcard match on sub-domains
			return nil, true
		}
		n = subNode
	}
	return nil, len(n) == 0 // exact match
}

func (m *DomainDB) String() string {
	return "Domain"
}
