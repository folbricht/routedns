package rdns

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// ASNDB holds blocklist rules based on ASN location. When an IP is queried,
// its ASN is looked up in a database and the result is compared to the
// blocklist rules.
type ASNDB struct {
	name      string
	loader    BlocklistLoader
	geoDB     *maxminddb.Reader
	geoDBFile string
	db        map[uint64]struct{}
}

var _ IPBlocklistDB = &ASNDB{}

// NewASNDB returns a new instance of a matcher for a list of ASN rules.
func NewASNDB(name string, loader BlocklistLoader, geoDBFile string) (*ASNDB, error) {
	if geoDBFile == "" {
		geoDBFile = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
	}
	geoDB, err := maxminddb.Open(geoDBFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open geo asn database file: %w", err)
	}

	db := make(map[uint64]struct{})
	// The map file is open from here on, so every way out of this function
	// has to close it.
	err = loader.Load(func() { db = make(map[uint64]struct{}) }, func(r string) error {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "#") || r == "" {
			return nil
		}
		r = strings.Split(r, "#")[0] // possible comment at the end of the line
		r = strings.TrimSpace(r)
		value, err := strconv.ParseUint(r, 10, 64) // GeoNames ID
		if err != nil {
			return fmt.Errorf("unable to parse asn id in rule '%s': %w", r, err)
		}
		db[value] = struct{}{}
		return nil
	})
	if err != nil {
		geoDB.Close()
		return nil, err
	}
	return &ASNDB{
		name:      name,
		geoDB:     geoDB,
		geoDBFile: geoDBFile,
		db:        db,
		loader:    loader,
	}, nil
}

func (m *ASNDB) Reload() (IPBlocklistDB, error) {
	db, err := NewASNDB(m.name, m.loader, m.geoDBFile)
	if errors.Is(err, ErrBlocklistUnchanged) {
		// The list could not be read, so the rules already loaded stand. They
		// are immutable and shared with the instance carrying them on, but the
		// map file is opened again so that it has a handle of its own to close.
		geoDB, oerr := maxminddb.Open(m.geoDBFile)
		if oerr != nil {
			return nil, fmt.Errorf("failed to open geo asn database file: %w", oerr)
		}
		return &ASNDB{
			name:      m.name,
			loader:    m.loader,
			geoDB:     geoDB,
			geoDBFile: m.geoDBFile,
			db:        m.db,
		}, err
	}
	return db, err
}

func (m *ASNDB) Match(ip net.IP) (*BlocklistMatch, bool) {
	var record struct {
		ASN          uint64 `maxminddb:"autonomous_system_number"`
		Organization string `maxminddb:"autonomous_system_organization"`
	}

	if err := m.geoDB.Lookup(ip, &record); err != nil {
		Log.Error("failed to lookup ip in geo location database", "ip", ip, "error", err)
		return nil, false
	}

	// Check if the ASN is on the blocklist
	if _, ok := m.db[record.ASN]; ok {
		return &BlocklistMatch{
			List: m.name,
			Rule: fmt.Sprintf("%d", record.ASN),
		}, true
	}
	return nil, false
}

func (m *ASNDB) Close() error {
	return m.geoDB.Close()
}

func (m *ASNDB) String() string {
	return "ASN-blocklist"
}
