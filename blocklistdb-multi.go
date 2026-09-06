package rdns

import (
	"errors"
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
	// A list that could not be read keeps the rules it already has, which is
	// what its loader means by errBlocklistUnchanged, while the lists beside
	// it still refresh. Only when none of them moved is there nothing to swap
	// in.
	newDBs := make([]BlocklistDB, 0, len(m.dbs))
	unchanged := 0
	for _, db := range m.dbs {
		n, err := db.Reload()
		switch {
		case errors.Is(err, errBlocklistUnchanged):
			unchanged++
			n = db
		case err != nil:
			return nil, err
		}
		newDBs = append(newDBs, n)
	}
	if unchanged == len(m.dbs) {
		return nil, errBlocklistUnchanged
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
