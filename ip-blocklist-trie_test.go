package rdns

import (
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	require.NoError(t, err)
	return n
}

// The biggest network covering an address is the one reported, whichever order
// the networks arrived in. A longer prefix inside one already on the list adds
// nothing, so it never becomes a rule of its own.
func TestIPBlocklistTrieShortestPrefix(t *testing.T) {
	for _, order := range [][]string{
		{"1.2.3.0/24", "1.2.0.0/16"},
		{"1.2.0.0/16", "1.2.3.0/24"},
	} {
		var tr ipBlocklistTrie
		for _, s := range order {
			tr.add(mustCIDR(t, s))
		}
		rule, ok := tr.hasIP(net.ParseIP("1.2.3.4"))
		require.True(t, ok, "order: %v", order)
		require.Equal(t, "1.2.0.0/16", rule, "order: %v", order)

		rule, ok = tr.hasIP(net.ParseIP("1.3.0.1"))
		require.False(t, ok, "order: %v", order)
		require.Empty(t, rule, "order: %v", order)
	}
}

// A default route covers everything, and is the one case where the root itself
// carries the rule.
func TestIPBlocklistTrieDefaultRoute(t *testing.T) {
	var v4, v6 ipBlocklistTrie
	v4.add(mustCIDR(t, "0.0.0.0/0"))
	v6.add(mustCIDR(t, "::/0"))

	rule, ok := v4.hasIP(net.ParseIP("8.8.8.8"))
	require.True(t, ok)
	require.Equal(t, "0.0.0.0/0", rule)

	rule, ok = v6.hasIP(net.ParseIP("2001:db8::1"))
	require.True(t, ok)
	require.Equal(t, "::/0", rule)
}

func TestIPBlocklistTrieEmpty(t *testing.T) {
	var tr ipBlocklistTrie
	tr.compact() // nothing to walk
	_, ok := tr.hasIP(net.ParseIP("1.2.3.4"))
	require.False(t, ok)
}

// compact drops what a network added over one already covering it left behind,
// and answers every address exactly as the trie did before it ran.
func TestIPBlocklistTrieCompact(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	randomIP := func() net.IP {
		return net.IPv4(byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)))
	}

	var tr ipBlocklistTrie
	var nets []*net.IPNet
	for range 2000 {
		ip := randomIP().To4()
		mask := net.CIDRMask(16+rng.Intn(17), 32)
		n := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
		nets = append(nets, n)
		tr.add(n)
	}
	// Supernets of a tenth of them, added last, so the nodes below each one are
	// left unreachable.
	for _, n := range nets[:200] {
		mask := net.CIDRMask(8, 32)
		tr.add(&net.IPNet{IP: n.IP.Mask(mask), Mask: mask})
	}

	probes := make([]net.IP, 0, 20000)
	for range 20000 {
		probes = append(probes, randomIP())
	}
	type verdict struct {
		rule string
		ok   bool
	}
	before := make([]verdict, 0, len(probes))
	for _, ip := range probes {
		rule, ok := tr.hasIP(ip)
		before = append(before, verdict{rule, ok})
	}

	nodesBefore := len(tr.nodes)
	tr.compact()
	require.Less(t, len(tr.nodes), nodesBefore, "compact dropped nothing")
	// The array is the memory, not the length: sizing it from the trie being
	// replaced would keep every dropped node resident behind the shorter slice.
	require.Equal(t, len(tr.nodes), cap(tr.nodes), "compact kept the array it dropped nodes from")

	for i, ip := range probes {
		rule, ok := tr.hasIP(ip)
		require.Equal(t, before[i].ok, ok, "ip: %v", ip)
		require.Equal(t, before[i].rule, rule, "ip: %v", ip)
	}
}
