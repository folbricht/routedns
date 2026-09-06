package rdns

import (
	"bytes"
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
//
// When includeSubdomains is true, bare entries like "domain.com" are treated as
// ".domain.com" (apex and all sub-domains). Entries that already use a leading
// "." or "*." prefix keep their original semantics. This is intended for
// blocklists where every line is meant to block both the apex and sub-domains
// (e.g. hagezi's "Wildcard Domains" lists).
type DomainDB struct {
	name              string
	root              *domainNode
	loader            BlocklistLoader
	includeSubdomains bool
}

// A node in the trie of domain labels, holding the rules that end on it. All
// three rule shapes describe the node of their base domain, so "domain.com",
// ".domain.com" and "*.domain.com" all record themselves on the node for
// domain.com and differ only in the flag they set.
type domainNode struct {
	children map[string]*domainNode
	flags    uint8
}

const (
	ruleExact   uint8 = 1 << iota // domain.com, the name itself
	ruleApexSub                   // .domain.com, the name and everything under it
	ruleSubOnly                   // *.domain.com, everything under it but not itself
)

// The longest name that can arrive in a query. Presentation-format names can
// exceed it when they carry escapes, which the match path handles separately.
const maxDomainName = 255

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
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	root := new(domainNode)
	for _, r := range rules {
		// Strip a trailing dot in case the list holds FQDNs, and force the
		// rule to lower case since queries are matched in lower case.
		r = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), "."))
		if r == "" {
			continue
		}

		// A bare wildcard only ever applied to the labels under it, of which
		// there are none here, so it's not an error, just nothing to record.
		if r == "*" {
			continue
		}

		// The prefix decides what the rule matches, the remainder is the base
		// domain that carries the flag. In subdomain mode a bare entry covers
		// the apex and everything under it, while entries that bring their own
		// prefix keep their meaning.
		flag := ruleExact
		switch {
		case strings.HasPrefix(r, "*."):
			r, flag = r[2:], ruleSubOnly
		case strings.HasPrefix(r, "."):
			r, flag = r[1:], ruleApexSub
		case includeSubdomains:
			flag = ruleApexSub
		}

		// Walk the labels from the TLD inwards, building the path as needed.
		n := root
		end := len(r)
		for {
			i := strings.LastIndexByte(r[:end], '.')
			label := r[i+1 : end]

			// Wildcards are only valid as the whole first label, which the
			// prefix above has already taken off.
			if strings.Contains(label, "*") {
				return nil, fmt.Errorf("invalid blocklist item: '%s'", label)
			}
			child, ok := n.children[label]
			if !ok {
				child = new(domainNode)
				if n.children == nil {
					n.children = make(map[string]*domainNode)
				}
				// Cloned so the node doesn't pin the whole rule line, which
				// is a slice of the same backing array.
				n.children[strings.Clone(label)] = child
			}
			n = child
			if i <= 0 {
				break
			}
			end = i
		}
		n.flags |= flag
	}
	return &DomainDB{name, root, loader, includeSubdomains}, nil
}

func (m *DomainDB) Reload() (BlocklistDB, error) {
	return newDomainDB(m.name, m.loader, m.includeSubdomains)
}

func (m *DomainDB) Match(msg *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	name := strings.TrimSuffix(msg.Question[0].Name, ".")

	// Lower-cased into a stack buffer, so the mixed-case names 0x20 encoding
	// produces don't cost an allocation like strings.ToLower would.
	var buf [maxDomainName]byte
	if len(name) <= len(buf) {
		return m.match(lowerASCII(buf[:len(name)], name))
	}
	return m.match([]byte(strings.ToLower(name)))
}

// match walks the labels of a lower-cased query name from the TLD inwards,
// stopping at the first rule that covers it.
func (m *DomainDB) match(name []byte) ([]net.IP, []string, *BlocklistMatch, bool) {
	n := m.root
	end := len(name)
	for end > 0 {
		i := bytes.LastIndexByte(name[:end], '.')

		// Indexing a map with a string conversion of a byte slice doesn't
		// allocate, so a query that doesn't match costs nothing on the heap.
		child, ok := n.children[string(name[i+1:end])]
		if !ok {
			return nil, nil, nil, false
		}
		if child.flags&ruleApexSub != 0 {
			return nil, nil, m.matched(".", name[i+1:]), true
		}
		if child.flags&ruleSubOnly != 0 && i > 0 { // only if a label remains to the left
			return nil, nil, m.matched("*.", name[i+1:]), true
		}
		n = child
		end = i
	}
	if n.flags&ruleExact != 0 {
		return nil, nil, m.matched("", name), true
	}
	return nil, nil, nil, false
}

// matched reports the rule that matched, rebuilt from the part of the query
// name it matched on.
func (m *DomainDB) matched(prefix string, name []byte) *BlocklistMatch {
	var b strings.Builder
	b.Grow(len(prefix) + len(name))
	b.WriteString(prefix)
	b.Write(name)
	return &BlocklistMatch{List: m.name, Rule: b.String()}
}

func (m *DomainDB) String() string {
	return "Domain"
}

// lowerASCII copies name into b, lower-cased. Domain names are ASCII, so
// byte-wise lowering is all that's needed.
func lowerASCII(b []byte, name string) []byte {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return b
}
