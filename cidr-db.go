package rdns

import (
	"fmt"
	"net"
)

type IPBlocklistDB interface {
	Reload() (IPBlocklistDB, error)
	Match(ip net.IP) (string, bool)
	fmt.Stringer
}

// CidrDB holds a list of IP networks that are used to block matching DNS responses.
type CidrDB struct {
	networks []*net.IPNet
	loader   BlocklistLoader
}

var _ IPBlocklistDB = &CidrDB{}

// NewCidrDB returns a new instance of a matcher for a list of networks.
func NewCidrDB(loader BlocklistLoader) (*CidrDB, error) {
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	var networks []*net.IPNet
	for _, r := range rules {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return nil, err
		}
		networks = append(networks, n)
	}

	return &CidrDB{networks, loader}, nil
}

func (m *CidrDB) Reload() (IPBlocklistDB, error) {
	return NewCidrDB(m.loader)
}

func (m *CidrDB) Match(ip net.IP) (string, bool) {
	for _, n := range m.networks {
		if n.Contains(ip) {
			return n.String(), true
		}
	}
	return "", false
}

func (m *CidrDB) String() string {
	return "CIDR-blocklist"
}
