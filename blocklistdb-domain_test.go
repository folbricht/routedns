package rdns

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// domainFormats builds a rule list in both storage formats. Everything the
// tables in this file assert about matching has to hold for either of them,
// so they run against both.
func domainFormats(t *testing.T, rules []string, includeSubdomains bool) map[string]BlocklistDB {
	t.Helper()
	loader := NewStaticLoader(rules)
	exact, err := newDomainDB("testlist", loader, includeSubdomains)
	require.NoError(t, err)
	compact, err := newDomainCompactDB("testlist", loader, includeSubdomains)
	require.NoError(t, err)
	return map[string]BlocklistDB{"exact": exact, "compact": compact}
}

func TestDomainDB(t *testing.T) {
	loader := NewStaticLoader([]string{
		"domain1.com.",    // exact match
		".domain2.com.",   // exact match and subdomains
		"x.domain2.com",   // above rule should take precedence
		"*.domain3.com",   // subdomains only
		"x.x.domain3.com", // more general wildcard above should take precedence
		"domain4.com",     // the more general rule below wins
		".domain4.com",
		".DOMAIN5.com",
	})

	tests := []struct {
		q     string
		match bool
	}{
		// exact
		{"domain1.com.", true},
		{"x.domain1.com.", false},

		// exact and subdomains
		{"domain2.com.", true},
		{"sub.domain2.com.", true},

		// wildcard (match only on subdomains)
		{"domain3.com.", false},
		{"sub.domain3.com.", true},

		// two rules for this, the generic one wins
		{"domain4.com.", true},
		{"sub.domain4.com.", true},

		// not matching
		{"unblocked.test.", false},
		{"com.", false},

		// capitalized query
		{"Domain1.com.", true},

		// match capital blocklist item
		{"domain5.com.", true},
	}
	for format, m := range domainFormats(t, loader.rules, false) {
		t.Run(format, func(t *testing.T) {
			for _, test := range tests {
				msg := new(dns.Msg)
				msg.SetQuestion(test.q, dns.TypeA)

				_, _, _, ok := m.Match(msg)
				require.Equal(t, test.match, ok, "query: %s", test.q)
			}
		})
	}
}

// TestDomainDBOverlap covers exact rules that overlap with more-specific
// rules. The exact-match flag must survive regardless of the order in which
// the overlapping rules are inserted.
func TestDomainDBOverlap(t *testing.T) {
	cases := []struct {
		name  string
		rules []string
		tests []struct {
			q     string
			match bool
		}
	}{
		{
			name:  "exact apex then exact subdomain",
			rules: []string{"domain.com", "sub.domain.com"},
			tests: []struct {
				q     string
				match bool
			}{
				{"domain.com.", true},
				{"sub.domain.com.", true},
				{"other.domain.com.", false},
			},
		},
		{
			name:  "exact subdomain then exact apex",
			rules: []string{"sub.domain.com", "domain.com"},
			tests: []struct {
				q     string
				match bool
			}{
				{"domain.com.", true},
				{"sub.domain.com.", true},
				{"other.domain.com.", false},
			},
		},
		{
			name:  "exact apex then deep exact subdomain",
			rules: []string{"domain.com", "sub.domain.com", "deep.sub.domain.com"},
			tests: []struct {
				q     string
				match bool
			}{
				{"domain.com.", true},
				{"sub.domain.com.", true},
				{"deep.sub.domain.com.", true},
				{"x.sub.domain.com.", false},
			},
		},
		{
			name:  "apex+sub rule then exact apex",
			rules: []string{".domain.com", "domain.com", ".other.com"},
			tests: []struct {
				q     string
				match bool
			}{
				{"domain.com.", true},
				{"sub.domain.com.", true},
				{"other.com.", true},
				{"sub.other.com.", true},
			},
		},
		{
			name:  "wildcard rule then exact apex",
			rules: []string{"*.domain.com", "*.other.com", "domain.com"},
			tests: []struct {
				q     string
				match bool
			}{
				{"domain.com.", true},
				{"sub.domain.com.", true},
				{"other.com.", false},
				{"sub.other.com.", true},
			},
		},
		{
			name:  "exact tld then exact apex under it",
			rules: []string{"com", "domain.com"},
			tests: []struct {
				q     string
				match bool
			}{
				{"com.", true},
				{"domain.com.", true},
				{"other.com.", false},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for format, m := range domainFormats(t, c.rules, false) {
				t.Run(format, func(t *testing.T) {
					for _, test := range c.tests {
						msg := new(dns.Msg)
						msg.SetQuestion(test.q, dns.TypeA)
						_, _, _, ok := m.Match(msg)
						require.Equal(t, test.match, ok, "rules=%v query=%s", c.rules, test.q)
					}
				})
			}
		})
	}
}

func TestDomainSubdomainDB(t *testing.T) {
	loader := NewStaticLoader([]string{
		"domain1.com",   // bare entry: apex + subdomains
		".domain2.com",  // explicit dot: apex + subdomains (unchanged)
		"*.domain3.com", // explicit wildcard: subdomains-only opt-out
		"DOMAIN4.com",   // capitalized bare entry
		"trailing.dot.com.",
	})

	tests := []struct {
		q     string
		match bool
	}{
		// bare entry matches apex and subdomains
		{"domain1.com.", true},
		{"sub.domain1.com.", true},
		{"deep.sub.domain1.com.", true},

		// leading-dot entry behaves identically
		{"domain2.com.", true},
		{"sub.domain2.com.", true},

		// wildcard entry remains subdomains-only (opt-out)
		{"domain3.com.", false},
		{"sub.domain3.com.", true},

		// capitalized blocklist entry, lowercase query
		{"domain4.com.", true},
		{"sub.domain4.com.", true},

		// trailing-dot entry handled
		{"trailing.dot.com.", true},
		{"sub.trailing.dot.com.", true},

		// non-matching
		{"unblocked.test.", false},
		{"com.", false},

		// capitalized query
		{"Domain1.com.", true},
	}
	for format, m := range domainFormats(t, loader.rules, true) {
		t.Run(format, func(t *testing.T) {
			for _, test := range tests {
				msg := new(dns.Msg)
				msg.SetQuestion(test.q, dns.TypeA)

				_, _, _, ok := m.Match(msg)
				require.Equal(t, test.match, ok, "query: %s", test.q)
			}
		})
	}
}

func TestDomainSubdomainDBError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"sub.*.com"},
		{"*domain.com"},
	}
	for _, test := range tests {
		loader := NewStaticLoader([]string{test.name})
		_, err := NewDomainSubdomainDB("testlist", loader)
		require.Error(t, err)
		_, err = NewDomainSubdomainCompactDB("testlist", loader)
		require.Error(t, err)
	}
}

func TestDomainDBError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"sub.*.com"},
		{"*domain.com"},
	}
	for _, test := range tests {
		loader := NewStaticLoader([]string{test.name})
		_, err := NewDomainDB("testlist", loader)
		require.Error(t, err)
		_, err = NewDomainCompactDB("testlist", loader)
		require.Error(t, err)
	}
}

// generateDomainRules builds a deterministic ruleset shaped like a real
// blocklist: mostly two-label entries, some deeper, in all three rule forms.
func generateDomainRules(n int) []string {
	rnd := rand.New(rand.NewSource(42))
	words := []string{"ads", "track", "cdn", "api", "metrics", "cloud", "static",
		"pixel", "log", "stats", "img", "click", "promo", "banner", "beacon"}
	tlds := []string{"com", "net", "org", "io", "xyz", "top", "info", "biz"}
	rules := make([]string, 0, n)
	for i := 0; i < n; i++ {
		domain := fmt.Sprintf("%s%d.%s", words[rnd.Intn(len(words))], i, tlds[rnd.Intn(len(tlds))])
		if rnd.Intn(4) == 0 { // a quarter of the rules sit a level deeper
			domain = words[rnd.Intn(len(words))] + "." + domain
		}
		switch rnd.Intn(3) {
		case 0:
			rules = append(rules, domain) // the name itself
		case 1:
			rules = append(rules, "."+domain) // the name and everything under it
		default:
			rules = append(rules, "*."+domain) // everything under it
		}
	}
	return rules
}

// A rule reduced to the base domain it applies to and what it covers.
type parsedDomainRule struct {
	domain    string
	apex, sub bool
	reported  string // the rule string a match on it reports
}

func parseDomainRules(rules []string, includeSubdomains bool) []parsedDomainRule {
	parsed := make([]parsedDomainRule, 0, len(rules))
	for _, r := range rules {
		r = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), "."))
		if r == "" || r == "*" {
			continue
		}
		p := parsedDomainRule{}
		switch {
		case strings.HasPrefix(r, "*."):
			p.domain, p.sub = r[2:], true
			p.reported = "*." + p.domain
		case strings.HasPrefix(r, "."):
			p.domain, p.apex, p.sub = r[1:], true, true
			p.reported = "." + p.domain
		case includeSubdomains:
			p.domain, p.apex, p.sub = r, true, true
			p.reported = "." + p.domain
		default:
			p.domain, p.apex = r, true
			p.reported = p.domain
		}
		parsed = append(parsed, p)
	}
	return parsed
}

// referenceDomainMatch applies the rule semantics from the DomainDB doc
// comment one rule at a time. A rule can only ever add a match, never take one
// away, so checking each independently is a valid oracle for what the trie
// does in one pass.
func referenceDomainMatch(parsed []parsedDomainRule, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, p := range parsed {
		if p.apex && name == p.domain {
			return true
		}
		if p.sub && strings.HasSuffix(name, "."+p.domain) {
			return true
		}
	}
	return false
}

// TestDomainDBGenerated checks the trie against the rule semantics applied
// directly, over a generated list and queries derived from it.
func TestDomainDBGenerated(t *testing.T) {
	for _, includeSubdomains := range []bool{false, true} {
		rules := generateDomainRules(500)
		parsed := parseDomainRules(rules, includeSubdomains)
		reported := make(map[string]bool, len(parsed))
		for _, p := range parsed {
			reported[p.reported] = true
		}

		var queries []string
		for _, p := range parsed {
			queries = append(queries, p.domain, "www."+p.domain, "a.b."+p.domain)
			if i := strings.IndexByte(p.domain, '.'); i > 0 {
				queries = append(queries, p.domain[i+1:]) // the parent domain
			}
		}
		for i := 0; i < 200; i++ {
			queries = append(queries, fmt.Sprintf("unlisted%d.example.net", i))
		}

		msg := new(dns.Msg)
		for format, db := range domainFormats(t, rules, includeSubdomains) {
			for _, q := range queries {
				msg.SetQuestion(dns.Fqdn(q), dns.TypeA)
				_, _, match, ok := db.Match(msg)
				require.Equal(t, referenceDomainMatch(parsed, q), ok,
					"format=%s subdomain-mode=%v query=%s", format, includeSubdomains, q)
				if !ok {
					require.Nil(t, match, "a miss must not build a match")
					continue
				}
				require.True(t, reported[match.Rule],
					"reported rule %q is not one of the rules loaded", match.Rule)
			}
		}
	}
}

func BenchmarkDomainDBMatch(b *testing.B) {
	for _, n := range []int{1000, 100000} {
		rules := generateDomainRules(n)
		db, err := newDomainDB("testlist", NewStaticLoader(rules), false)
		require.NoError(b, err)

		// A name that matches the last rule loaded, one that shares its TLD
		// but nothing else, and a mixed-case name to cover the lowering path.
		hit := "www." + strings.TrimPrefix(strings.TrimPrefix(rules[len(rules)-1], "*."), ".")
		for _, q := range []string{hit, "www.example.com", "WWW.ExAmPlE.CoM"} {
			b.Run(fmt.Sprintf("rules=%d/name=%s", n, q), func(b *testing.B) {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(q), dns.TypeA)
				b.ReportAllocs()
				for b.Loop() {
					_, _, _, _ = db.Match(msg)
				}
			})
		}
	}
}

func BenchmarkDomainDBBuild(b *testing.B) {
	for _, n := range []int{10000, 100000} {
		rules := generateDomainRules(n)
		loader := NewStaticLoader(rules)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := newDomainDB("testlist", loader, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestDomainDBLabelStorage covers the two ways a label is stored, in the node
// itself or in the blob, either side of the boundary between them, and rules
// that no valid query could reach.
func TestDomainDBLabelStorage(t *testing.T) {
	short := strings.Repeat("a", domainInlineLabel)   // stored in the node
	long := strings.Repeat("b", domainInlineLabel+1)  // stored in the blob
	longest := strings.Repeat("c", maxDomainLabel)    // the longest allowed
	overlong := strings.Repeat("d", maxDomainLabel+1) // longer than any query

	rules := []string{
		short + ".com",
		long + ".com",
		longest + ".com",
		overlong + ".com",                // skipped, unreachable
		"# Comment line, as lists carry", // skipped, no label could be queried
		"sub." + long + ".net",
		"." + long + ".net",
	}
	tests := []struct {
		q     string
		match bool
	}{
		{short + ".com.", true},
		{long + ".com.", true},
		{longest + ".com.", true},
		{overlong + ".com.", false},
		{strings.Repeat("d", maxDomainLabel) + ".com.", false},
		{short + "a.com.", false}, // one byte longer than a rule
		{long[:domainInlineLabel] + ".com.", false},
		{"sub." + long + ".net.", true},
		{"other." + long + ".net.", true}, // covered by the .prefix rule
	}
	for format, m := range domainFormats(t, rules, false) {
		t.Run(format, func(t *testing.T) {
			for _, test := range tests {
				msg := new(dns.Msg)
				msg.SetQuestion(test.q, dns.TypeA)
				_, _, _, ok := m.Match(msg)
				require.Equal(t, test.match, ok, "query: %s", test.q)
			}
		})
	}
}

// TestDomainDBGrowth loads enough rules to rebuild the lookup table several
// times over, and checks every one of them still matches afterwards.
func TestDomainDBGrowth(t *testing.T) {
	rules := generateDomainRules(20000)
	parsed := parseDomainRules(rules, false)

	msg := new(dns.Msg)
	for format, m := range domainFormats(t, rules, false) {
		t.Run(format, func(t *testing.T) {
			for _, p := range parsed {
				q := p.domain
				if !p.apex { // a sub-domains-only rule needs one to match
					q = "www." + q
				}
				msg.SetQuestion(dns.Fqdn(q), dns.TypeA)
				_, _, _, ok := m.Match(msg)
				require.True(t, ok, "rule %q, query %q", p.reported, q)
			}
		})
	}
}

func TestDomainDBEmpty(t *testing.T) {
	for format, m := range domainFormats(t, nil, false) {
		t.Run(format, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion("example.com.", dns.TypeA)
			_, _, match, ok := m.Match(msg)
			require.False(t, ok)
			require.Nil(t, match)
		})
	}
}

// TestDomainDBSharedLabels covers the same label sitting under several parents,
// which the lookup table has to keep apart.
func TestDomainDBSharedLabels(t *testing.T) {
	rules := []string{
		"www.one.com",
		".www.two.com",
		"*.www.three.com",
		"www.four.net",
		"deep.www.one.com",
	}
	tests := []struct {
		q     string
		match bool
	}{
		{"www.one.com.", true},
		{"www.two.com.", true},
		{"www.three.com.", false}, // wildcard covers sub-domains only
		{"sub.www.three.com.", true},
		{"www.four.net.", true},
		{"deep.www.one.com.", true},
		{"www.four.com.", false}, // right labels, wrong parents
		{"www.one.net.", false},
		{"www.five.com.", false},
		{"deep.www.four.net.", false},
	}
	for format, m := range domainFormats(t, rules, false) {
		t.Run(format, func(t *testing.T) {
			for _, test := range tests {
				msg := new(dns.Msg)
				msg.SetQuestion(test.q, dns.TypeA)
				_, _, _, ok := m.Match(msg)
				require.Equal(t, test.match, ok, "query: %s", test.q)
			}
		})
	}
}

// The trie a build hands back is sized to what it holds, so a list that shrank
// does not leave the database holding what the larger one needed.
func TestDomainDBShrink(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "list.txt")
	var big strings.Builder
	for i := range 20000 {
		fmt.Fprintf(&big, "host%d.example.com\n", i)
	}
	require.NoError(t, os.WriteFile(name, []byte(big.String()), 0644))

	db, err := NewDomainDB("testlist", NewFileLoader(name, FileLoaderOptions{}))
	require.NoError(t, err)
	require.Greater(t, cap(db.trie.nodes), 20000)

	require.NoError(t, os.WriteFile(name, []byte("only.example.com\n"), 0644))
	reloaded, err := db.Reload()
	require.NoError(t, err)

	trie := reloaded.(*DomainDB).trie
	require.Less(t, cap(trie.nodes), 100, "the trie kept the nodes the larger list needed")
	require.Less(t, len(trie.slots), 100, "the table kept the size the larger list needed")

	msg := new(dns.Msg)
	msg.SetQuestion("only.example.com.", dns.TypeA)
	_, _, _, ok := reloaded.Match(msg)
	require.True(t, ok)
}
