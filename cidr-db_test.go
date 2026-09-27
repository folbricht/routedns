package rdns

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCidrDB(t *testing.T) {
	loader := NewStaticLoader([]string{
		"127.0.0.0/24",
		"1.2.0.0/16",
		"2a03:2880:f101:83::0/64",
	})
	db, err := NewCidrDB("testlist", loader)
	require.NoError(t, err)

	tests := []struct {
		ip    net.IP
		match bool
	}{
		{ip: net.ParseIP("127.0.0.1"), match: true},
		{ip: net.ParseIP("1.2.0.0"), match: true},
		{ip: net.ParseIP("192.168.1.1"), match: false},
		{ip: net.ParseIP("2a03:2880:f101:83:1:1:1:1"), match: true},
		{ip: net.ParseIP("::1"), match: false},
		{ip: nil, match: false},
		{ip: net.IP{}, match: false},
	}

	for _, test := range tests {
		_, ok := db.Match(test.ip)
		require.Equal(t, test.match, ok)
	}

}

// A network written in the v4-mapped form names v4 addresses and has to match
// them. ParseCIDR keeps it 16 bytes wide, which put a 128 bit path into the v4
// trie: the rule itself never matched, and because the mapped prefix is 80 zero
// bits followed by ones, a query for an address low enough to walk 32 zero bits
// matched instead.
func TestCidrDBV4Mapped(t *testing.T) {
	db, err := NewCidrDB("testlist", NewStaticLoader([]string{
		"::ffff:1.2.3.4/128", // one address, written the long way
		"::ffff:5.6.7.0/120", // a /24, written the long way
		"::ffff:9.9.0.0",     // no mask at all, both a colon and dots
		"2001:db8:1::/48",    // a real v6 network alongside
	}))
	require.NoError(t, err)

	tests := []struct {
		ip    string
		match bool
		rule  string
	}{
		{"1.2.3.4", true, "1.2.3.4/32"},
		{"1.2.3.5", false, ""},
		{"5.6.7.1", true, "5.6.7.0/24"},
		{"5.6.8.1", false, ""},
		{"9.9.0.0", true, "9.9.0.0/32"},
		// The address a 128 bit path in the v4 trie used to answer for.
		{"0.0.0.0", false, ""},
		{"2001:db8:1::1", true, "2001:db8:1::/48"},
		{"2001:db8:2::1", false, ""},
	}
	for _, test := range tests {
		match, ok := db.Match(net.ParseIP(test.ip))
		require.Equal(t, test.match, ok, "ip: %s", test.ip)
		if test.match {
			require.Equal(t, test.rule, match.Rule, "ip: %s", test.ip)
		}
	}
}

// The mapping occupies the first 96 bits, so a network covering all of it is
// all of v4, and anything shorter reaches outside it and stays v6.
func TestCidrDBV4MappedBoundary(t *testing.T) {
	all, err := NewCidrDB("testlist", NewStaticLoader([]string{"::ffff:0:0/96"}))
	require.NoError(t, err)
	match, ok := all.Match(net.ParseIP("203.0.113.9"))
	require.True(t, ok, "::ffff:0:0/96 is every v4 address")
	require.Equal(t, "0.0.0.0/0", match.Rule)

	// One bit shorter takes in addresses that are not v4 at all.
	wider, err := NewCidrDB("testlist", NewStaticLoader([]string{"::ffff:0:0/95"}))
	require.NoError(t, err)
	_, ok = wider.Match(net.ParseIP("203.0.113.9"))
	require.False(t, ok, "a network reaching outside the mapping is not a v4 one")
	_, ok = wider.Match(net.ParseIP("::ffff:0:0"))
	require.False(t, ok, "and a v4-mapped query is matched as the v4 address it is")

	// The v6 default route still covers v6 only.
	def, err := NewCidrDB("testlist", NewStaticLoader([]string{"::/0"}))
	require.NoError(t, err)
	_, ok = def.Match(net.ParseIP("2001:db8::1"))
	require.True(t, ok)
	_, ok = def.Match(net.ParseIP("203.0.113.9"))
	require.False(t, ok, "::/0 is not a v4 rule")
}

// A query that matches nothing carries no match, as the name databases already
// did. It is checked against every address in a response, so a miss is the
// common case and must not allocate one to throw away.
func TestCidrDBNoMatchIsNil(t *testing.T) {
	db, err := NewCidrDB("testlist", NewStaticLoader([]string{"10.0.0.0/8", "2001:db8::/32"}))
	require.NoError(t, err)

	for _, ip := range []string{"1.2.3.4", "2001:db9::1"} {
		match, ok := db.Match(net.ParseIP(ip))
		require.False(t, ok, "ip: %s", ip)
		require.Nil(t, match, "ip: %s", ip)
	}
	match, ok := db.Match(net.ParseIP("10.1.2.3"))
	require.True(t, ok)
	require.Equal(t, "10.0.0.0/8", match.Rule)
}
