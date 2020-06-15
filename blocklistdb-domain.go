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
	root   node
	loader BlocklistLoader
}

type node map[string]node

var _ BlocklistDB = &DomainDB{}

// NewDomainDB returns a new instance of a matcher for a list of regular expressions.
func NewDomainDB(loader BlocklistLoader) (*DomainDB, error) {
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	root := make(node)
	for _, r := range rules {
		r = strings.TrimSpace(r)

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
	return &DomainDB{root, loader}, nil
}

func (m *DomainDB) Reload() (BlocklistDB, error) {
	return NewDomainDB(m.loader)
}

func (m *DomainDB) Match(q dns.Question) (net.IP, string, bool) {
	s := strings.TrimSuffix(q.Name, ".")
	var matched []string
	parts := strings.Split(s, ".")
	n := m.root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		subNode, ok := n[part]
		if !ok {
			return nil, "", false
		}
		matched = append(matched, part)
		if _, ok := subNode[""]; ok { // exact and sub-domain match
			return nil, matchedDomainParts(".", matched), true
		}
		if _, ok := subNode["*"]; ok && i > 0 { // wildcard match on sub-domains
			return nil, matchedDomainParts("*.", matched), true
		}
		n = subNode
	}
	return nil, matchedDomainParts("", matched), len(n) == 0 // exact match
}

func (m *DomainDB) String() string {
	return "Domain"
}

// Turn a list of matched domain fragments into a domain (rule)
func matchedDomainParts(prefix string, p []string) string {
	for i := len(p)/2 - 1; i >= 0; i-- {
		opp := len(p) - 1 - i
		p[i], p[opp] = p[opp], p[i]
	}
	return prefix + strings.Join(p, ".")
}
