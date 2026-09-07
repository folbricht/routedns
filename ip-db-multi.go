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
	// A list that could not be read hands back the rules it already has while
	// the lists beside it refresh, so the group is rebuilt whole either way.
	// The databases it is rebuilt from are new instances, which is what lets
	// the group they came from be closed once this one is in place.
	newDBs := make([]IPBlocklistDB, 0, len(m.dbs))
	// Every way out of here but the last one leaves the group unbuilt, and the
	// databases gathered for it are then nobody's to close but ours.
	keep := false
	defer func() {
		if !keep {
			for _, db := range newDBs {
				db.Close()
			}
		}
	}()
	changed := false
	for _, db := range m.dbs {
		n, err := db.Reload()
		switch {
		case errors.Is(err, ErrBlocklistUnchanged): // n holds the rules it had
		case err != nil:
			return MultiIPDB{}, err
		default:
			changed = true
		}
		newDBs = append(newDBs, n)
	}
	group, err := NewMultiIPDB(newDBs...)
	if err != nil {
		return MultiIPDB{}, err
	}
	keep = true
	if !changed { // nothing moved, so the group says so as its databases did
		return group, ErrBlocklistUnchanged
	}
	return group, nil
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
