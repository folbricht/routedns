package rdns

import (
	"net"
	"strings"
)

// CidrDB holds a list of IP networks that are used to block matching DNS responses.
// Network ranges are stored in a trie (one for IP4 and one for IP6) to allow for
// efficient matching
type CidrDB struct {
	ip4, ip6 *ipBlocklistTrie
	loader   BlocklistLoader
}

var _ IPBlocklistDB = &CidrDB{}

// NewCidrDB returns a new instance of a matcher for a list of networks.
func NewCidrDB(loader BlocklistLoader) (*CidrDB, error) {
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	db := &CidrDB{
		ip4: new(ipBlocklistTrie),
		ip6: new(ipBlocklistTrie),
	}
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "#") || r == "" {
			continue
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
	return NewCidrDB(m.loader)
}

func (m *CidrDB) Match(ip net.IP) (string, bool) {
	if addr := ip.To4(); addr == nil {
		return m.ip6.hasIP(ip)
	}
	return m.ip4.hasIP(ip)
}

func (m *CidrDB) Close() error {
	return nil
}

func (m *CidrDB) String() string {
	return "CIDR-blocklist"
}
