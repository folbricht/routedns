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

	m, err := NewRegexpDB(`(^|\.)block\.test`, `(^|\.)evil\.test`)
	require.NoError(t, err)

	opt := BlocklistOptions{
		BlocklistDB: m,
	}
	b, err := NewBlocklist(r, opt)
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
}
