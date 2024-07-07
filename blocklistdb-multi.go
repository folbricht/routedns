package rdns

import (
	"net"

	"github.com/miekg/dns"
)

// MultiDB wraps multiple blocklist DBs and performs queries over all of them.
type MultiDB struct {
	dbs []BlocklistDB
}

var _ BlocklistDB = MultiDB{}

// NewMultiDB returns a new instance of a wrapper for blocklists
func NewMultiDB(dbs ...BlocklistDB) (MultiDB, error) {
	return MultiDB{dbs}, nil
}

func (m MultiDB) Reload() (BlocklistDB, error) {
	var newDBs []BlocklistDB
	for _, db := range m.dbs {
		n, err := db.Reload()
		if err != nil {
			return nil, err
		}
		newDBs = append(newDBs, n)
	}
	return NewMultiDB(newDBs...)
}

func (m MultiDB) Match(q *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	for _, db := range m.dbs {
		if ip, name, match, ok := db.Match(q); ok {
			return ip, name, match, ok
		}
	}
	return nil, nil, nil, false
}

func (m MultiDB) String() string {
	return "Multi-Blocklist"
}
