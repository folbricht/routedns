package rdns

import (
	"fmt"
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

// Names the trie would file under something the list never carried are skipped.
// A label's length is held in a byte, so a 300 byte label would wrap to 44 and
// block a name of 44 characters, and the walk drops a leading dot, so
// ".example.com" would block the apex. Both are dead entries in the map this
// replaced, and both stay unmatched here.
func TestHostsDBUnqueryableNames(t *testing.T) {
	long := strings.Repeat("a", 300)
	m, err := NewHostsDB("testlist", NewStaticLoader([]string{
		"0.0.0.0 " + long + ".example.com",
		"0.0.0.0 .apex.example.com",
		"0.0.0.0 blocked.example.com",
	}))
	require.NoError(t, err)

	for _, name := range []string{
		long + ".example.com.",
		strings.Repeat("a", int(uint8(len(long)))) + ".example.com.", // the truncated length
		"apex.example.com.",
		"example.com.",
	} {
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

// A PTR entry holds no more names than a PTR query is answered with. Lists that
// sinkhole to a single address, an unspecified one or 127.0.0.1, would
// otherwise gather every name they carry under the one reverse address.
func TestHostsDBPTRBounded(t *testing.T) {
	var rules []string
	for i := range 100 {
		rules = append(rules, fmt.Sprintf("127.0.0.1 blocked%d.example.com", i))
	}
	m, err := NewHostsDB("testlist", NewStaticLoader(rules))
	require.NoError(t, err)
	require.Len(t, m.ptrMap["1.0.0.127.in-addr.arpa."], maxPTRResponses)

	msg := new(dns.Msg)
	msg.SetQuestion("1.0.0.127.in-addr.arpa.", dns.TypePTR)
	_, names, _, ok := m.Match(msg)
	require.True(t, ok)
	require.Equal(t, "blocked0.example.com", names[0])
}

// A line is an address followed by names, and a comment can begin anywhere on
// it. Words on a line that carries neither are not names.
func TestHostsDBLineShape(t *testing.T) {
	m, err := NewHostsDB("testlist", NewStaticLoader([]string{
		"This list is provided as is",         // an un-commented header
		"# 0.0.0.0 commented.example.com",     // a whole line commented out
		"1.2.3.4",                             // an address with no names
		"1.2.3.4 spoof.example.com # comment", // a comment after a name
		"0.0.0.0 ads.example.com # tracker",
	}))
	require.NoError(t, err)

	for _, name := range []string{
		"list.", "is.", "provided.", "as.", // words of the header line
		"commented.example.com.",   // behind a comment
		"comment.", "tracker.", "", // words of the inline comments
	} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
		_, _, _, ok := m.Match(msg)
		require.False(t, ok, "query: %s", name)
	}

	// The names on those lines are unaffected, spoofed and blocked as written.
	msg := new(dns.Msg)
	msg.SetQuestion("spoof.example.com.", dns.TypeA)
	ips, _, _, ok := m.Match(msg)
	require.True(t, ok)
	require.Equal(t, []net.IP{net.ParseIP("1.2.3.4")}, ips)

	msg = new(dns.Msg)
	msg.SetQuestion("ads.example.com.", dns.TypeA)
	ips, _, _, ok = m.Match(msg)
	require.True(t, ok)
	require.Nil(t, ips)

	// A comment is not a name in the reverse map either.
	require.Equal(t, []string{"spoof.example.com"}, m.ptrMap["4.3.2.1.in-addr.arpa."])
}
