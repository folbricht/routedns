package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDomainMatcher(t *testing.T) {
	m, err := NewDomainMatcher(
		"domain1.com.",    // exact match
		".domain2.com.",   // exact match and subdomains
		"x.domain2.com",   // above rule should take precendence
		"*.domain3.com",   // subdomains only
		"x.x.domain3.com", // more specific wildcard should take precedence
	)
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

		// // wildcard (match only on subdomains)
		{"domain3.com.", false},
		{"sub.domain3.com.", true},

		// not matching
		{"unblocked.test.", false},
		{"com.", false},
	}
	for _, test := range tests {
		q := dns.Question{Name: test.q, Qtype: dns.TypeA, Qclass: dns.ClassINET}
		_, ok := m.Match(q)
		require.Equal(t, test.match, ok, "query: %s", test.q)
	}
}

func TestDomainMatcherError(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"sub.*.com"},
		{"*domain.com"},
	}
	for _, test := range tests {
		_, err := NewDomainMatcher(test.name)
		require.Error(t, err)
	}
}
