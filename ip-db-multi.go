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
	// Unlike the name-based group, this one owns its databases and closes them
	// when it is replaced, so a database that reported nothing to change
	// cannot be carried into the new group: the old group would close it out
	// from under the new one. The whole group therefore keeps what it has
	// until every list in it can be read again, and the ones already rebuilt
	// are closed rather than dropped on the floor.
	newDBs := make([]IPBlocklistDB, 0, len(m.dbs))
	closeAll := func() {
		for _, db := range newDBs {
			db.Close()
		}
	}
	for _, db := range m.dbs {
		n, err := db.Reload()
		if err != nil {
			closeAll()
			return MultiIPDB{}, err
		}
		newDBs = append(newDBs, n)
	}
	return NewMultiIPDB(newDBs...)
}

func (m MultiIPDB) Match(ip net.IP) (*BlocklistMatch, bool) {
	for _, db := range m.dbs {
		if match, ok := db.Match(ip); ok {
			return match, ok
		}
	}
	return nil, false
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
