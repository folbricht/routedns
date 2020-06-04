package rdns

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIPDB holds blocklist rules based on location. When an IP is queried,
// its location is looked up in a database and the result is compared to the
// blocklist rules.
type GeoIPDB struct {
	loader    BlocklistLoader
	geoDB     *maxminddb.Reader
	geoDBFile string
	db        map[uint64]struct{}
}

var _ IPBlocklistDB = &GeoIPDB{}

// NewGeoIPDB returns a new instance of a matcher for a location rules.
func NewGeoIPDB(loader BlocklistLoader, geoDBFile string) (*GeoIPDB, error) {
	if geoDBFile == "" {
		geoDBFile = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	}
	geoDB, err := maxminddb.Open(geoDBFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open geo location database file: %w", err)
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
			return nil, fmt.Errorf("unable to parse geoname id in rule '%s': %w", r, err)
		}
		db[value] = struct{}{}
	}
	return &GeoIPDB{
		geoDB:     geoDB,
		geoDBFile: geoDBFile,
		db:        db,
	}, nil
}

func (m *GeoIPDB) Reload() (IPBlocklistDB, error) {
	return NewGeoIPDB(m.loader, m.geoDBFile)
}

func (m *GeoIPDB) Match(ip net.IP) (string, bool) {
	var record struct {
		Continent struct {
			GeoNameID uint64 `maxminddb:"geoname_id"`
		} `maxminddb:"continent"`
		Country struct {
			GeoNameID uint64 `maxminddb:"geoname_id"`
		} `maxminddb:"country"`
		City struct {
			GeoNameID uint64 `maxminddb:"geoname_id"`
		} `maxminddb:"city"`
	}

	if err := m.geoDB.Lookup(ip, &record); err != nil {
		Log.WithField("ip", ip).WithError(err).Error("failed to lookup ip in geo location database")
		return "", false
	}

	// Try to find the continent, country, or city GeoName ID in the blocklist
	for _, key := range []uint64{record.Continent.GeoNameID, record.Country.GeoNameID, record.City.GeoNameID} {
		if _, ok := m.db[key]; ok {
			return fmt.Sprintf("%d", key), true
		}
	}
	return "", false
}

func (m *GeoIPDB) Close() error {
	return m.geoDB.Close()
}

func (m *GeoIPDB) String() string {
	return "GeoIP-blocklist"
}
