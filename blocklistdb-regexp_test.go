package rdns

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func regexpDBRules(n int) []string {
	rules := make([]string, 0, n)
	for i := range n {
		rules = append(rules, fmt.Sprintf(`(^|\.)ads%d\.example\.org`, i))
	}
	return rules
}

func newRegexpDBForTest(tb testing.TB, n int) *RegexpDB {
	tb.Helper()
	db, err := NewRegexpDB("test", NewStaticLoader(regexpDBRules(n)))
	require.NoError(tb, err)
	return db
}

func regexpQuery(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	return q
}

// Matching cost must not scale in allocations with the number of rules. A
// query carrying upper case is what makes this visible: lowering it copies,
// and doing that inside the rule loop copies once per rule.
func TestRegexpDBMatchDoesNotAllocatePerRule(t *testing.T) {
	const rules = 200
	db := newRegexpDBForTest(t, rules)
	q := regexpQuery("WWW.ExAmPlE.CoM.")

	allocs := testing.AllocsPerRun(50, func() {
		_, _, _, _ = db.Match(q)
	})

	// Lowering the name per rule puts this in the hundreds. The bound is
	// generous rather than exact because the race detector allocates on its
	// own account, which is enough to break an equality check.
	require.Less(t, allocs, float64(rules)/10, "allocations scale with the rule count")
}

// The rules are compiled from lower-case patterns, so matching has to be
// case-insensitive in the query name however many rules are searched.
func TestRegexpDBMatchIsCaseInsensitive(t *testing.T) {
	db, err := NewRegexpDB("test", NewStaticLoader([]string{
		`(^|\.)first\.example\.org`,
		`(^|\.)block\.example\.org`,
	}))
	require.NoError(t, err)

	// Matches the second rule, so the search passes over the first one.
	_, _, match, ok := db.Match(regexpQuery("X.BlOcK.ExAmPlE.OrG."))
	require.True(t, ok)
	require.Equal(t, "test", match.List)
	require.Equal(t, `(^|\.)block\.example\.org`, match.Rule)

	_, _, match, ok = db.Match(regexpQuery("WWW.ExAmPlE.CoM."))
	require.False(t, ok)
	require.Nil(t, match, "a miss must not build a match")
}

func BenchmarkRegexpDBMatchMiss(b *testing.B) {
	for _, n := range []int{50, 200} {
		for _, name := range []string{"www.example.com.", "WWW.ExAmPlE.CoM."} {
			b.Run(fmt.Sprintf("rules=%d/name=%s", n, name), func(b *testing.B) {
				db := newRegexpDBForTest(b, n)
				q := regexpQuery(name)
				b.ReportAllocs()
				for b.Loop() {
					_, _, _, _ = db.Match(q)
				}
			})
		}
	}
}
