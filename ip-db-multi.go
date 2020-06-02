package rdns

import (
	"net"
)

// MultiIPDB wraps multiple blocklist CIDR DBs and performs queries over all of them.
type MultiIPDB struct {
	dbs []IPBlocklistDB
}

var _ IPBlocklistDB = MultiIPDB{}

// NewMultiIPDB returns a new instance of a wrapper for blocklists
func NewMultiIPDB(dbs ...IPBlocklistDB) (MultiIPDB, error) {
	return MultiIPDB{dbs}, nil
}

func (m MultiIPDB) Reload() (IPBlocklistDB, error) {
	var newDBs []IPBlocklistDB
	for _, db := range m.dbs {
		n, err := db.Reload()
		if err != nil {
			return MultiIPDB{}, err
		}
		newDBs = append(newDBs, n)
	}
	return NewMultiIPDB(newDBs...)
}

func (m MultiIPDB) Match(ip net.IP) (string, bool) {
	for _, db := range m.dbs {
		if rule, ok := db.Match(ip); ok {
			return rule, ok
		}
	}
	return "", false
}

func (m MultiIPDB) Close() error {
	var closeErr error
	for _, db := range m.dbs {
		if err := db.Close(); closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (m MultiIPDB) String() string {
	return "Multi-IP-blocklist"
}
