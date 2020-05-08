package rdns

import (
	"net"
)

// CidrMultiDB wraps multiple blocklist CIDR DBs and performs queries over all of them.
type MultiCidrDB struct {
	dbs []IPBlocklistDB
}

var _ IPBlocklistDB = MultiCidrDB{}

// NewMultiDB returns a new instance of a wrapper for blocklists
func NewMultiCidrDB(dbs ...IPBlocklistDB) (MultiCidrDB, error) {
	return MultiCidrDB{dbs}, nil
}

func (m MultiCidrDB) Reload() (IPBlocklistDB, error) {
	var newDBs []IPBlocklistDB
	for _, db := range m.dbs {
		n, err := db.Reload()
		if err != nil {
			return MultiCidrDB{}, err
		}
		newDBs = append(newDBs, n)
	}
	return NewMultiCidrDB(newDBs...)
}

func (m MultiCidrDB) Match(ip net.IP) (string, bool) {
	for _, db := range m.dbs {
		if rule, ok := db.Match(ip); ok {
			return rule, ok
		}
	}
	return "", false
}

func (m MultiCidrDB) String() string {
	return "Multi-CIDR-blocklist"
}
