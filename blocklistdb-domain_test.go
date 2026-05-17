package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

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

	m, err := NewDomainDB("testlist", loader)
	require.NoError(t, err)

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
	for _, test := range tests {
		msg := new(dns.Msg)
		msg.SetQuestion(test.q, dns.TypeA)

		_, _, _, ok := m.Match(msg)
		require.Equal(t, test.match, ok, "query: %s", test.q)
	}
}

// TestDomainDBOverlap covers exact rules that overlap with more-specific
// rules. The trie's exact-match marker must survive regardless of the
// order in which the overlapping rules are inserted.
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
			name:  "apex+sub rule then exact apex (shared dot sentinel untouched)",
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
			name:  "wildcard rule then exact apex (shared star sentinel untouched)",
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
			m, err := NewDomainDB("testlist", NewStaticLoader(c.rules))
			require.NoError(t, err)
			for _, test := range c.tests {
				msg := new(dns.Msg)
				msg.SetQuestion(test.q, dns.TypeA)
				_, _, _, ok := m.Match(msg)
				require.Equal(t, test.match, ok, "rules=%v query=%s", c.rules, test.q)
			}
		})
	}
}

func TestDomainSubdomainDB(t *testing.T) {
	loader := NewStaticLoader([]string{
		"domain1.com",     // bare entry: apex + subdomains
		".domain2.com",    // explicit dot: apex + subdomains (unchanged)
		"*.domain3.com",   // explicit wildcard: subdomains-only opt-out
		"DOMAIN4.com",     // capitalized bare entry
		"trailing.dot.com.",
	})

	m, err := NewDomainSubdomainDB("testlist", loader)
	require.NoError(t, err)

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
	for _, test := range tests {
		msg := new(dns.Msg)
		msg.SetQuestion(test.q, dns.TypeA)

		_, _, _, ok := m.Match(msg)
		require.Equal(t, test.match, ok, "query: %s", test.q)
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
	}
}
