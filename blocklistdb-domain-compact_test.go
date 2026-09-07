package rdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestDomainCompactMatchesExact runs a generated list through both storage
// formats and requires the same answer from each, rule string included. The
// exact matcher is the oracle: a difference is either a bug or one of the
// fingerprint collisions the compact format trades exactness for, and at this
// size those are a once in ten billion event.
func TestDomainCompactMatchesExact(t *testing.T) {
	for _, includeSubdomains := range []bool{false, true} {
		rules := generateDomainRules(20000)
		loader := NewStaticLoader(rules)
		exact, err := newDomainDB("testlist", loader, includeSubdomains)
		require.NoError(t, err)
		compact, err := newDomainCompactDB("testlist", loader, includeSubdomains)
		require.NoError(t, err)

		var queries []string
		for _, p := range parseDomainRules(rules, includeSubdomains) {
			queries = append(queries, p.domain, "www."+p.domain, "a.b."+p.domain)
			if i := strings.IndexByte(p.domain, '.'); i > 0 {
				queries = append(queries, p.domain[i+1:])
			}
		}
		for i := 0; i < 20000; i++ {
			queries = append(queries, fmt.Sprintf("unlisted%d.example.net", i))
		}

		msg := new(dns.Msg)
		for _, q := range queries {
			msg.SetQuestion(dns.Fqdn(q), dns.TypeA)
			_, _, wantMatch, want := exact.Match(msg)
			_, _, gotMatch, got := compact.Match(msg)
			require.Equal(t, want, got, "subdomain-mode=%v query=%s", includeSubdomains, q)
			require.Equal(t, wantMatch.GetRule(), gotMatch.GetRule(), "query=%s", q)
		}
	}
}

// TestDomainCompactSeeded checks that two databases built from the same rules
// hash them differently, which is what keeps a colliding name from being worth
// computing in advance, while answering identically.
func TestDomainCompactSeeded(t *testing.T) {
	rules := generateDomainRules(1000)
	loader := NewStaticLoader(rules)
	first, err := newDomainCompactDB("testlist", loader, false)
	require.NoError(t, err)
	second, err := newDomainCompactDB("testlist", loader, false)
	require.NoError(t, err)
	require.NotEqual(t, first.fingerprints.seed, second.fingerprints.seed)
	require.NotEqual(t, first.fingerprints.entries, second.fingerprints.entries)

	msg := new(dns.Msg)
	for _, p := range parseDomainRules(rules, false) {
		q := p.domain
		if !p.apex {
			q = "www." + q
		}
		msg.SetQuestion(dns.Fqdn(q), dns.TypeA)
		_, _, _, one := first.Match(msg)
		_, _, _, two := second.Match(msg)
		require.True(t, one, "query %s", q)
		require.Equal(t, one, two)
	}
}

func BenchmarkDomainCompactMatch(b *testing.B) {
	for _, n := range []int{1000, 100000} {
		rules := generateDomainRules(n)
		db, err := newDomainCompactDB("testlist", NewStaticLoader(rules), false)
		require.NoError(b, err)

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

func BenchmarkDomainCompactBuild(b *testing.B) {
	for _, n := range []int{10000, 100000} {
		rules := generateDomainRules(n)
		loader := NewStaticLoader(rules)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := newDomainCompactDB("testlist", loader, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
