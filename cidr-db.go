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
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	db := &CidrDB{
		name:   name,
		ip4:    new(ipBlocklistTrie),
		ip6:    new(ipBlocklistTrie),
		loader: loader,
	}
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "#") || r == "" {
			continue
		}
		// Append a mask suffix if there isn't one already
		if !strings.Contains(r, "/") {
			if strings.Contains(r, ".") { // ip4
				r += "/32"
			} else if strings.Contains(r, ":") { // ip6
				r += "/128"
			}
		}
		ip, n, err := net.ParseCIDR(r)
		if err != nil {
			return nil, err
		}
		if addr := ip.To4(); addr == nil {
			db.ip6.add(n)
		} else {
			db.ip4.add(n)
		}
	}
	return db, nil
}

func (m *CidrDB) Reload() (IPBlocklistDB, error) {
	return NewCidrDB(m.name, m.loader)
}

func (m *CidrDB) Match(ip net.IP) (*BlocklistMatch, bool) {
	if addr := ip.To4(); addr == nil {
		rule, ok := m.ip6.hasIP(ip)
		return &BlocklistMatch{List: m.name, Rule: rule}, ok
	}
	rule, ok := m.ip4.hasIP(ip)
	return &BlocklistMatch{List: m.name, Rule: rule}, ok
}

func (m *CidrDB) Close() error {
	return nil
}

func (m *CidrDB) String() string {
	return "CIDR-blocklist"
}
