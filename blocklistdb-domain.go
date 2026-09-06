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
	trie              domainTrie
	loader            BlocklistLoader
	includeSubdomains bool
}

// domainTrie holds the rules as a trie of domain labels in three flat pieces:
// every node in one array, the labels too long to sit inside a node in one
// blob, and one open-addressed table mapping a node and a label to the child
// under it. None of it holds a pointer, so a list of millions of rules costs
// the garbage collector three objects to mark rather than one per node.
type domainTrie struct {
	nodes []domainNode
	blob  []byte
	slots []uint64 // parent, child and a tag byte, zero when empty
}

// A node carries its label and the rules that end on it. All three rule shapes
// describe the node of their base domain, so "domain.com", ".domain.com" and
// "*.domain.com" all record themselves on the node for domain.com and differ
// only in the flag they set.
//
// Labels of domainInlineLabel bytes or fewer, which is most of them, sit in the
// node itself. Longer ones give up the first four bytes of the same field to an
// offset into the blob.
type domainNode struct {
	label  [6]byte
	length uint8
	flags  uint8
}

const domainInlineLabel = 6

const (
	ruleExact       uint8 = 1 << iota // domain.com, the name itself
	ruleApexSub                       // .domain.com, the name and everything under it
	ruleSubOnly                       // *.domain.com, everything under it but not itself
	ruleHasChildren                   // more specific rules sit below this node
)

// The longest name that can arrive in a query. Presentation-format names can
// exceed it when they carry escapes, which the match path handles separately.
const maxDomainName = 255

var _ BlocklistDB = &DomainDB{}

// NewDomainDB returns a new instance of a matcher for a list of domain rules.
func NewDomainDB(name string, loader BlocklistLoader) (*DomainDB, error) {
	return newDomainDB(name, loader, false, 0, 0)
}

// NewDomainSubdomainDB is like NewDomainDB but treats bare entries as matching
// the apex and all sub-domains. See DomainDB for details.
func NewDomainSubdomainDB(name string, loader BlocklistLoader) (*DomainDB, error) {
	return newDomainDB(name, loader, true, 0, 0)
}

// nodes and blob are the size of the trie this one is replacing, which is what
// a refresh builds into rather than growing towards. See newDomainBuilder.
func newDomainDB(name string, loader BlocklistLoader, includeSubdomains bool, nodes, blob int) (*DomainDB, error) {
	b := newDomainBuilder(nodes, blob)
	reset := func() { b = newDomainBuilder(nodes, blob) }
	err := domainRules(loader, includeSubdomains, reset, func(domain string, flag uint8) error {
		// Walk the labels from the TLD inwards, building the path as needed.
		n := uint32(0)
		end := len(domain)
		for {
			i := strings.LastIndexByte(domain[:end], '.')
			child, err := b.child(n, domain[i+1:end])
			if err != nil {
				return err
			}
			n = child
			if i <= 0 {
				break
			}
			end = i
		}
		b.nodes[n].flags |= flag
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &DomainDB{name, b.done(), loader, includeSubdomains}, nil
}

// domainRules interprets the rules of a list, handing each one to record as the
// domain it applies to and the flag it sets there. Both storage formats build
// from this, so the syntax is read in one place.
func domainRules(loader BlocklistLoader, includeSubdomains bool, reset func(), record func(domain string, flag uint8) error) error {
	return loader.Load(reset, func(r string) error {
		// Strip a trailing dot in case the list holds FQDNs, and force the
		// rule to lower case since queries are matched in lower case.
		r = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), "."))
		if r == "" {
			return nil
		}

		// A bare wildcard only ever applied to the labels under it, of which
		// there are none here, so it's not an error, just nothing to record.
		if r == "*" {
			return nil
		}

		// Lists carry comment lines and other noise, and a name with a label
		// over the DNS limit could never be queried anyway, so such a rule is
		// skipped rather than failing the list it came in.
		if hasOverlongLabel(r) {
			return nil
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

		// Wildcards are only valid as the whole first label, which the prefix
		// above has already taken off.
		if i := strings.IndexByte(r, '*'); i >= 0 {
			start := strings.LastIndexByte(r[:i], '.') + 1
			end := strings.IndexByte(r[i:], '.')
			if end < 0 {
				end = len(r)
			} else {
				end += i
			}
			return fmt.Errorf("invalid blocklist item: '%s'", r[start:end])
		}

		return record(r, flag)
	})
}

func (m *DomainDB) Reload() (BlocklistDB, error) {
	nodes, blob := m.trie.sizes()
	return newDomainDB(m.name, m.loader, m.includeSubdomains, nodes, blob)
}

func (m *DomainDB) Match(msg *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	var buf [maxDomainName]byte
	return m.match(domainQueryName(msg, buf[:]))
}

// domainQueryName returns the name a query asks about, lower-cased and without
// its trailing dot, copied into buf when it fits. Names that fit cost no
// allocation, including the mixed-case ones 0x20 encoding produces, which
// strings.ToLower would allocate for.
func domainQueryName(msg *dns.Msg, buf []byte) []byte {
	name := strings.TrimSuffix(msg.Question[0].Name, ".")
	if len(name) <= len(buf) {
		return lowerASCII(buf[:len(name)], name)
	}
	return []byte(strings.ToLower(name))
}

// match walks the labels of a lower-cased query name from the TLD inwards,
// stopping at the first rule that covers it.
func (m *DomainDB) match(name []byte) ([]net.IP, []string, *BlocklistMatch, bool) {
	node := uint32(0)
	flags := m.trie.nodes[0].flags
	end := len(name)
	for end > 0 {
		if flags&ruleHasChildren == 0 {
			return nil, nil, nil, false // nothing more specific exists
		}
		i := bytes.LastIndexByte(name[:end], '.')
		child, ok := trieFind(&m.trie, node, name[i+1:end])
		if !ok {
			return nil, nil, nil, false
		}
		flags = m.trie.nodes[child].flags
		if prefix, ok := domainRuleAt(flags, i > 0); ok {
			return nil, nil, domainMatched(m.name, prefix, name[i+1:]), true
		}
		node = child
		end = i
	}
	if flags&ruleExact != 0 {
		return nil, nil, domainMatched(m.name, "", name), true
	}
	return nil, nil, nil, false
}

// domainRuleAt reports whether the rules recorded on a node cover a query that
// has walked down to it, and with what prefix the rule is written. more says
// whether the query still has labels to the left of this node, which is what
// separates a wildcard rule from an apex one.
func domainRuleAt(flags uint8, more bool) (string, bool) {
	if flags&ruleApexSub != 0 { // .domain.com
		return ".", true
	}
	if flags&ruleSubOnly != 0 && more { // *.domain.com
		return "*.", true
	}
	return "", false
}

// domainMatched reports the rule that matched, rebuilt from the part of the
// query name it matched on.
func domainMatched(list, prefix string, name []byte) *BlocklistMatch {
	var b strings.Builder
	b.Grow(len(prefix) + len(name))
	b.WriteString(prefix)
	b.Write(name)
	return &BlocklistMatch{List: list, Rule: b.String()}
}

func (m *DomainDB) String() string {
	return "Domain"
}

// hasOverlongLabel reports whether any label of the rule is longer than a
// domain label may be.
func hasOverlongLabel(r string) bool {
	for {
		i := strings.IndexByte(r, '.')
		if i < 0 {
			return len(r) > maxDomainLabel
		}
		if i > maxDomainLabel {
			return true
		}
		r = r[i+1:]
	}
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
