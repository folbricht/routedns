package main

import (
	"sync/atomic"
	"testing"

	rdns "github.com/folbricht/routedns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A resolver that answers everything and counts what it was asked.
type countingResolver struct {
	name string
	hits atomic.Int64
}

func (r *countingResolver) Resolve(q *dns.Msg, ci rdns.ClientInfo) (*dns.Msg, error) {
	r.hits.Add(1)
	a := new(dns.Msg)
	a.SetReply(q)
	return a, nil
}

func (r *countingResolver) String() string { return r.name }

// A static allowlist is compiled in allowlist-format, not in the blocklist's.
// Read as a regexp, "allowed.com" also matches names that merely contain it,
// which is what sends an unrelated name to the allowlist resolver here.
func TestBlocklistAllowlistFormat(t *testing.T) {
	upstream := &countingResolver{name: "upstream"}
	allow := &countingResolver{name: "allow"}

	resolvers := map[string]rdns.Resolver{"upstream": upstream, "allow": allow}
	err := instantiateGroup("bl", group{
		Type:              "blocklist-v2",
		Resolvers:         []string{"upstream"},
		Blocklist:         []string{"blocked.com"},
		Allowlist:         []string{"allowed.com"},
		AllowlistFormat:   "domain",
		AllowListResolver: "allow",
	}, resolvers)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("notallowedxcom.", dns.TypeA)
	_, err = resolvers["bl"].Resolve(q, rdns.ClientInfo{})
	require.NoError(t, err)
	require.Zero(t, allow.hits.Load(), "unrelated name matched the allowlist")
	require.Equal(t, int64(1), upstream.hits.Load())

	// The allowlist still does its job for the name it names.
	q.SetQuestion("allowed.com.", dns.TypeA)
	_, err = resolvers["bl"].Resolve(q, rdns.ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, int64(1), allow.hits.Load())
}

// Without allowlist-format the list keeps being read in the blocklist's
// format, which is how such a config has always behaved.
func TestBlocklistAllowlistFormatDefaultsToBlocklist(t *testing.T) {
	upstream := &countingResolver{name: "upstream"}
	allow := &countingResolver{name: "allow"}

	resolvers := map[string]rdns.Resolver{"upstream": upstream, "allow": allow}
	err := instantiateGroup("bl", group{
		Type:              "blocklist-v2",
		Resolvers:         []string{"upstream"},
		BlocklistFormat:   "domain",
		Blocklist:         []string{"blocked.com"},
		Allowlist:         []string{"allowed.com"},
		AllowListResolver: "allow",
	}, resolvers)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("notallowedxcom.", dns.TypeA)
	_, err = resolvers["bl"].Resolve(q, rdns.ClientInfo{})
	require.NoError(t, err)
	require.Zero(t, allow.hits.Load())
}
