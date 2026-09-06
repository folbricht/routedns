package rdns

import (
	"errors"
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
	// A list that could not be read keeps the rules it already has while the
	// lists beside it still refresh. Unlike the name-based group, this one
	// closes its databases when it is replaced, so a database that reported
	// nothing to change is carried across as a copy that owns whatever it
	// holds rather than as the instance the old group is about to close.
	newDBs := make([]IPBlocklistDB, 0, len(m.dbs))
	closeAll := func() {
		for _, db := range newDBs {
			db.Close()
		}
	}
	unchanged := 0
	for _, db := range m.dbs {
		n, err := db.Reload()
		if errors.Is(err, ErrBlocklistUnchanged) {
			r, ok := db.(reusableIPDB)
			if !ok {
				closeAll()
				return MultiIPDB{}, err
			}
			if n, err = r.reuse(); err != nil {
				closeAll()
				return MultiIPDB{}, err
			}
			unchanged++
		} else if err != nil {
			closeAll()
			return MultiIPDB{}, err
		}
		newDBs = append(newDBs, n)
	}
	if unchanged == len(m.dbs) { // nothing moved, so there is nothing to swap in
		closeAll()
		return MultiIPDB{}, ErrBlocklistUnchanged
	}
	return NewMultiIPDB(newDBs...)
}

// An IP database that can produce an equivalent of itself, holding the same
// rules but owning whatever needs closing, so that it can be carried into a
// new group while the group it came from is closed.
type reusableIPDB interface {
	reuse() (IPBlocklistDB, error)
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
