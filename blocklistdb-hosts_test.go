package rdns

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestHostsDB(t *testing.T) {
	loader := NewStaticLoader([]string{
		"# some comment",
		"              ",
		"127.0.0.1   domain1.com",
		"0.0.0.0     domain2.com",
		"0.0.0.0     domain3.com domain4.com. ",
		"::          domain5.com",
		"::1         domain6.com",
		"192.168.1.1 domain6.com",
		"127.0.0.1   DOMAIN7.com",
		"0.0.0.0     DOMAIN8.com",
		"0.0.0.0     domain9.com",
		"10.0.0.1    domain9.com",
	})

	m, err := NewHostsDB("testlist", loader)
	require.NoError(t, err)

	tests := []struct {
		q     string
		typ   uint16
		match bool
		ip    []net.IP
	}{
		{"domain1.com.", dns.TypeA, true, []net.IP{net.ParseIP("127.0.0.1")}},
		{"domain2.com.", dns.TypeA, true, nil},
		{"domain4.com.", dns.TypeA, true, nil},
		{"domain5.com.", dns.TypeA, true, nil},
		{"domain6.com.", dns.TypeA, true, []net.IP{net.ParseIP("192.168.1.1")}},
		{"domain6.com.", dns.TypeAAAA, true, []net.IP{net.ParseIP("::1")}},
		{"domainX.com.", dns.TypeA, false, nil},
		{"Domain1.com.", dns.TypeA, true, []net.IP{net.ParseIP("127.0.0.1")}},
		{"domain7.com.", dns.TypeA, true, []net.IP{net.ParseIP("127.0.0.1")}},
		// A blocked name matches regardless of the case it was written in, and
		// blocking one type blocks the other.
		{"domain8.com.", dns.TypeA, true, nil},
		{"domain2.com.", dns.TypeAAAA, true, nil},
		// A name carrying both a block rule and an address answers with the
		// address.
		{"domain9.com.", dns.TypeA, true, []net.IP{net.ParseIP("10.0.0.1")}},
		// Only the name itself is blocked, not what sits under it.
		{"sub.domain2.com.", dns.TypeA, false, nil},
	}
	for _, test := range tests {
		msg := new(dns.Msg)
		msg.SetQuestion(test.q, test.typ)
		ip, _, match, ok := m.Match(msg)

		require.Equal(t, test.match, ok, "query: %s", test.q)
		require.EqualValues(t, test.ip, ip, "query: %s", test.q)
		if test.match {
			require.Equal(t, "testlist", match.List, "query: %s", test.q)
		} else {
			require.Nil(t, match, "query: %s", test.q)
		}
	}
}

// A name that only blocks reports the rule it matched, the same as a name that
// spoofs an address does.
func TestHostsDBRule(t *testing.T) {
	m, err := NewHostsDB("testlist", NewStaticLoader([]string{
		"0.0.0.0   blocked.example.com",
		"1.2.3.4   spoofed.example.com",
	}))
	require.NoError(t, err)

	for _, name := range []string{"blocked.example.com", "spoofed.example.com"} {
		msg := new(dns.Msg)
		msg.SetQuestion(name+".", dns.TypeA)
		_, _, match, ok := m.Match(msg)
		require.True(t, ok, "query: %s", name)
		require.Equal(t, name, match.Rule)
	}
}

// PTR answers come from the entries that spoof an address. An unspecified
// address is shared by every blocked name in a list, so no reverse entry is
// recorded for it.
func TestHostsDBPTR(t *testing.T) {
	m, err := NewHostsDB("testlist", NewStaticLoader([]string{
		"0.0.0.0   blocked1.example.com",
		"0.0.0.0   blocked2.example.com",
		"1.2.3.4   spoofed.example.com",
	}))
	require.NoError(t, err)

	msg := new(dns.Msg)
	msg.SetQuestion("4.3.2.1.in-addr.arpa.", dns.TypePTR)
	_, names, _, ok := m.Match(msg)
	require.True(t, ok)
	require.Equal(t, []string{"spoofed.example.com"}, names)

	msg = new(dns.Msg)
	msg.SetQuestion("0.0.0.0.in-addr.arpa.", dns.TypePTR)
	_, names, match, ok := m.Match(msg)
	require.False(t, ok)
	require.Nil(t, names)
	require.Nil(t, match)
}

// A hosts list of the shape a blocklist has holds no per-rule allocation, so
// what it costs is the trie rather than a map entry for every name.
func TestHostsDBBlockedInTrie(t *testing.T) {
	m, err := NewHostsDB("testlist", NewStaticLoader([]string{
		"0.0.0.0   blocked1.example.com",
		"0.0.0.0   blocked2.example.com",
		"1.2.3.4   spoofed.example.com",
	}))
	require.NoError(t, err)

	require.Len(t, m.filters, 1)
	require.Len(t, m.ptrMap, 1)
}

// A name with a label longer than a label may be is skipped. It could never be
// reached by a query, and the trie holds a label's length in a byte.
func TestHostsDBOverlongLabel(t *testing.T) {
	long := strings.Repeat("a", 300)
	m, err := NewHostsDB("testlist", NewStaticLoader([]string{
		"0.0.0.0 " + long + ".example.com",
		"0.0.0.0 blocked.example.com",
	}))
	require.NoError(t, err)

	for _, name := range []string{long + ".example.com.", "aa.example.com.", "example.com."} {
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeA)
		_, _, _, ok := m.Match(msg)
		require.False(t, ok, "query: %s", name)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.com.", dns.TypeA)
	_, _, _, ok := m.Match(msg)
	require.True(t, ok)
}
