package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestBlocklistRegexp(t *testing.T) {
	var ci ClientInfo
	q := new(dns.Msg)
	r := new(TestResolver)

	loader := NewStaticLoader([]string{
		`(^|\.)block\.test`,
		`(^|\.)evil\.test`,
	})
	m, err := NewRegexpDB("testlist", loader)
	require.NoError(t, err)

	opt := BlocklistOptions{
		BlocklistDB: m,
	}
	b, err := NewBlocklist("test-bl", r, opt)
	require.NoError(t, err)

	// First query a domain not blocked. Should be passed through to the resolver
	q.SetQuestion("test.com.", dns.TypeA)
	_, err = b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())

	// One domain from the blocklist should come back with NXDOMAIN
	q.SetQuestion("x.evil.test.", dns.TypeA)
	a, err := b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
	require.Equal(t, dns.RcodeNameError, a.Rcode)

	// A mixed-case variation of a blocked name must still be blocked (DNS
	// names are case-insensitive); it must not be forwarded upstream.
	q.SetQuestion("X.EvIl.TeSt.", dns.TypeA)
	a, err = b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
	require.Equal(t, dns.RcodeNameError, a.Rcode)
}

func TestBlocklistAllow(t *testing.T) {
	var ci ClientInfo
	q := new(dns.Msg)
	r := new(TestResolver)

	blockloader := NewStaticLoader([]string{
		`(^|\.)block\.test`,
		`(^|\.)evil\.test`,
	})
	allowloader := NewStaticLoader([]string{
		`(^|\.)good\.evil\.test`,
	})
	blockDB, err := NewRegexpDB("testlist", blockloader)
	require.NoError(t, err)
	allowDB, err := NewRegexpDB("testlist", allowloader)
	require.NoError(t, err)

	opt := BlocklistOptions{
		BlocklistDB: blockDB,
		AllowlistDB: allowDB,
	}
	b, err := NewBlocklist("test-bl", r, opt)
	require.NoError(t, err)

	// First query a domain not blocked. Should be passed through to the resolver
	q.SetQuestion("test.com.", dns.TypeA)
	_, err = b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())

	// One domain from the blocklist should come back with NXDOMAIN
	q.SetQuestion("x.evil.test.", dns.TypeA)
	a, err := b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r.HitCount())
	require.Equal(t, dns.RcodeNameError, a.Rcode)

	// One domain blocklist that also matches the allowlist should go through
	q.SetQuestion("good.evil.test.", dns.TypeA)
	_, err = b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 2, r.HitCount())

	// A mixed-case blocked name must still be blocked (not forwarded).
	q.SetQuestion("X.EvIl.TeSt.", dns.TypeA)
	a, err = b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 2, r.HitCount())
	require.Equal(t, dns.RcodeNameError, a.Rcode)

	// A mixed-case variation of an allowlisted name must still be allowed
	// through, consistent with case-insensitive DNS semantics.
	q.SetQuestion("GoOd.EvIl.TeSt.", dns.TypeA)
	_, err = b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 3, r.HitCount())
}
