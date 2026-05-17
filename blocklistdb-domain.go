package rdns

import (
	"fmt"
	"maps"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DomainDB holds a list of domain strings (potentially with wildcards). Matching
// logic:
// domain.com: matches just domain.com and not subdomains
// .domain.com: matches domain.com and all subdomains
// *.domain.com: matches all subdomains but not domain.com
//
// When includeSubdomains is true, bare entries like "domain.com" are treated as
// ".domain.com" (apex and all sub-domains). Entries that already use a leading
// "." or "*." prefix keep their original semantics. This is intended for
// blocklists where every line is meant to block both the apex and sub-domains
// (e.g. hagezi's "Wildcard Domains" lists).
type DomainDB struct {
	name              string
	root              node
	loader            BlocklistLoader
	includeSubdomains bool
}

type node map[string]node

// exactKey marks a node as an exact-match terminal that must also act
// as an interior node for more-specific rules. A nil/empty node still
// means an exact terminal on its own; exactKey is only added when the
// same node additionally carries children or other sentinels so the
// marker isn't masked. The value can never collide with a real label
// (rules are split on ".", so labels never contain ".") nor with the
// "" (apex+sub) or "*" (sub-only) sentinels.
const exactKey = "."

var _ BlocklistDB = &DomainDB{}

// NewDomainDB returns a new instance of a matcher for a list of domain rules.
func NewDomainDB(name string, loader BlocklistLoader) (*DomainDB, error) {
	return newDomainDB(name, loader, false)
}

// NewDomainSubdomainDB is like NewDomainDB but treats bare entries as matching
// the apex and all sub-domains. See DomainDB for details.
func NewDomainSubdomainDB(name string, loader BlocklistLoader) (*DomainDB, error) {
	return newDomainDB(name, loader, true)
}

func newDomainDB(name string, loader BlocklistLoader, includeSubdomains bool) (*DomainDB, error) {
	// Large lists (e.g. hagezi NRD) produce huge numbers of identical
	// terminal nodes: empty leaves, "{"": empty}" (.X.tld), and
	// "{"*": empty}" (*.X.tld). Empty leaves are represented as the nil
	// node so they cost zero allocations. The two depth-1 shapes share
	// a single map instance per build. Any later rule that descends
	// through one of them clones first so it doesn't corrupt sibling
	// paths that share the same instance.
	dotNode := node{"": nil}
	starNode := node{"*": nil}

	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	root := make(node)
	for _, r := range rules {
		r = strings.TrimSpace(r)

		// Strip trailing . in case the list has FQDN names with . suffixes.
		r = strings.TrimSuffix(r, ".")

		// Force all domain names to lower case
		r = strings.ToLower(r)

		// In subdomain-matching mode, treat bare entries as ".entry" so they
		// match the apex and all sub-domains. Leave entries that already
		// start with "." or "*." alone.
		if includeSubdomains && r != "" && !strings.HasPrefix(r, ".") && !strings.HasPrefix(r, "*.") {
			r = "." + r
		}

		// Break up the domain into its parts and iterate backwards over them, building
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
				switch {
				case i == 0:
					subNode = nil
				case i == 1 && parts[0] == "":
					subNode = dotNode
				case i == 1 && parts[0] == "*":
					subNode = starNode
				default:
					subNode = make(node)
				}
				n[part] = subNode
				n = subNode
				continue
			}

			// The path segment already exists.
			if i == 0 {
				// This rule is an exact match terminating here. A
				// nil/empty leaf already means an exact terminal, and a
				// "" sentinel already matches the apex, so in both
				// cases there's nothing to add. Otherwise the node also
				// acts as an interior node for more-specific rules, so
				// record an explicit exact marker that survives
				// alongside the children. Clone shared shapes before
				// mutating so siblings sharing the instance aren't
				// corrupted.
				if len(subNode) == 0 {
					break
				}
				if _, apex := subNode[""]; apex {
					break
				}
				if isSharedShape(subNode) {
					subNode = maps.Clone(subNode)
					n[part] = subNode
				}
				subNode[exactKey] = nil
				break
			}

			// Descending through an existing segment. Clone/expand
			// shared shapes so sibling paths that share the instance
			// aren't corrupted, preserving an exact terminal that a
			// shorter rule stored here as a nil leaf.
			if isSharedShape(subNode) {
				if subNode == nil {
					subNode = node{exactKey: nil}
				} else {
					subNode = maps.Clone(subNode)
				}
				n[part] = subNode
			}
			n = subNode
		}
	}
	return &DomainDB{name, root, loader, includeSubdomains}, nil
}

// isSharedShape reports whether n looks like one of the build-time
// sentinels: a nil empty leaf, {"": nil} (the .X dot-sentinel), or
// {"*": nil} (the *.X star-sentinel). The build path never produces
// nodes of these shapes outside the sentinel paths, so a shape match
// safely identifies a (possibly shared) instance that must be cloned
// before mutation.
func isSharedShape(n node) bool {
	switch len(n) {
	case 0:
		return n == nil
	case 1:
		if v, ok := n[""]; ok {
			return v == nil
		}
		if v, ok := n["*"]; ok {
			return v == nil
		}
	}
	return false
}

func (m *DomainDB) Reload() (BlocklistDB, error) {
	return newDomainDB(m.name, m.loader, m.includeSubdomains)
}

func (m *DomainDB) Match(msg *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	q := msg.Question[0]
	s := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	var matched []string
	parts := strings.Split(s, ".")
	n := m.root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		subNode, ok := n[part]
		if !ok {
			return nil, nil, nil, false
		}
		matched = append(matched, part)
		if _, ok := subNode[""]; ok { // exact and sub-domain match
			return nil,
				nil,
				&BlocklistMatch{
					List: m.name,
					Rule: matchedDomainParts(".", matched),
				},
				true
		}
		if _, ok := subNode["*"]; ok && i > 0 { // wildcard match on sub-domains
			return nil,
				nil,
				&BlocklistMatch{
					List: m.name,
					Rule: matchedDomainParts("*.", matched),
				},
				true
		}
		n = subNode
	}
	_, exact := n[exactKey]
	return nil,
		nil,
		&BlocklistMatch{
			List: m.name,
			Rule: matchedDomainParts("", matched),
		},
		len(n) == 0 || exact // exact match
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
