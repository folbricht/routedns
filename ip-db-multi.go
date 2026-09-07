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
	// A list that could not be read hands back the rules it already has while
	// the lists beside it refresh. Those are new instances, which is what lets
	// the group they came from be closed once this one is in place.
	newDBs := make([]IPBlocklistDB, 0, len(m.dbs))
	// Until the group is built, what was gathered for it is ours to close.
	keep := false
	defer func() {
		if !keep {
			for _, db := range newDBs {
				db.Close()
			}
		}
	}()
	for _, db := range m.dbs {
		n, err := db.Reload()
		if err != nil {
			if n == nil { // nothing to put in its place, so the group stays as it is
				return nil, err
			}
			Log.Warn("failed to load rules, continuing with the ones already loaded",
				"error", err)
		}
		newDBs = append(newDBs, n)
	}
	group, err := NewMultiIPDB(newDBs...)
	if err != nil {
		return nil, err
	}
	keep = true
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
