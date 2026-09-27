package rdns

import (
	"net"
	"strings"
)

// CidrDB holds a list of IP networks that are used to block matching DNS responses.
// Network ranges are stored in a trie (one for IP4 and one for IP6) to allow for
// efficient matching
type CidrDB struct {
	name     string
	ip4, ip6 *ipBlocklistTrie
	loader   BlocklistLoader
}

var _ IPBlocklistDB = &CidrDB{}

// NewCidrDB returns a new instance of a matcher for a list of networks.
func NewCidrDB(name string, loader BlocklistLoader) (*CidrDB, error) {
	db := &CidrDB{
		name:   name,
		ip4:    new(ipBlocklistTrie),
		ip6:    new(ipBlocklistTrie),
		loader: loader,
	}
	err := loader.Load(func() {
		db.ip4, db.ip6 = new(ipBlocklistTrie), new(ipBlocklistTrie)
	}, func(r string) error {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "#") || r == "" {
			return nil
		}
		// Append a mask suffix if there isn't one already. The colon decides,
		// since the v4-mapped form of an address carries both it and the dots.
		if !strings.Contains(r, "/") {
			if strings.Contains(r, ":") { // ip6, the v4-mapped form included
				r += "/128"
			} else if strings.Contains(r, ".") { // ip4
				r += "/32"
			}
		}
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return err
		}
		if n, ok := as4(n); ok {
			db.ip4.add(n)
		} else {
			db.ip6.add(n)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	db.ip4.compact()
	db.ip6.compact()
	return db, nil
}

// as4 returns a network as the v4 network it describes, and whether it is one.
// ParseCIDR keeps a rule written in the v4-mapped form 16 bytes wide, so
// "::ffff:1.2.3.4/128" arrives as a 128 bit network even though it names a
// single v4 address; adding that to the v4 trie walks 96 bits of the mapped
// prefix that a query, which is matched 4 bytes wide, never reaches.
//
// A prefix shorter than the 96 bits of that mapping covers addresses outside
// it as well, so it is not a v4 network and stays where it was written.
func as4(n *net.IPNet) (*net.IPNet, bool) {
	if len(n.IP) == net.IPv4len {
		return n, true
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return n, false
	}
	ones, bits := n.Mask.Size()
	if bits != 8*net.IPv6len || ones < 8*(net.IPv6len-net.IPv4len) {
		return n, false
	}
	return &net.IPNet{IP: ip4, Mask: net.CIDRMask(ones-8*(net.IPv6len-net.IPv4len), 8*net.IPv4len)}, true
}

func (m *CidrDB) Reload() (IPBlocklistDB, error) {
	db, err := NewCidrDB(m.name, m.loader)
	if err != nil {
		// The rules already loaded stand. The tries are immutable, so the
		// instance carrying them on shares them.
		return &CidrDB{name: m.name, ip4: m.ip4, ip6: m.ip6, loader: m.loader}, err
	}
	return db, err
}

func (m *CidrDB) Match(ip net.IP) (*BlocklistMatch, bool) {
	// A nil/empty IP can't be in any network; guard here so the trie
	// lookup never indexes into a zero-length slice and panics.
	if len(ip) == 0 {
		return nil, false
	}
	trie := m.ip4
	if addr := ip.To4(); addr == nil {
		trie = m.ip6
	}
	rule, ok := trie.hasIP(ip)
	if !ok {
		return nil, false
	}
	return &BlocklistMatch{List: m.name, Rule: rule}, true
}

func (m *CidrDB) Close() error {
	return nil
}

func (m *CidrDB) String() string {
	return "CIDR-blocklist"
}
