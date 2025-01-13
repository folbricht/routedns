package rdns

import (
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

// NewASN returns a new instance of a matcher for a ASN rules.
func NewASNDB(name string, loader BlocklistLoader, geoDBFile string) (*ASNDB, error) {
	if geoDBFile == "" {
		geoDBFile = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
	}
	geoDB, err := maxminddb.Open(geoDBFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open geo asn database file: %w", err)
	}

	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}

	db := make(map[uint64]struct{})
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "#") || r == "" {
			continue
		}
		r = strings.Split(r, "#")[0] // possible comment at the end of the line
		r = strings.TrimSpace(r)
		value, err := strconv.ParseUint(r, 10, 64) // GeoNames ID
		if err != nil {
			return nil, fmt.Errorf("unable to parse asn id in rule '%s': %w", r, err)
		}
		db[value] = struct{}{}
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
	return NewASNDB(m.name, m.loader, m.geoDBFile)
}

func (m *ASNDB) Match(ip net.IP) (*BlocklistMatch, bool) {
	var record struct {
		ASN          uint64 `maxminddb:"autonomous_system_number"`
		Organization string `maxminddb:"autonomous_system_organization"`
	}

	if err := m.geoDB.Lookup(ip, &record); err != nil {
		Log.WithField("ip", ip).WithError(err).Error("failed to lookup ip in geo location database")
		return nil, false
	}

	fmt.Println(record)

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
