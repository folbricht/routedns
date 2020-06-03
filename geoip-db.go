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
	db        map[string]struct{}
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

	// Parse the rules, check for correctness then build a map with the keys being the cleaned string
	// rules. So matching happens on the full rule, not just the ID in it. That way, all the rules can
	// be stored in one map, no need to have a separate map for city and country for example.
	db := make(map[string]struct{})
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "#") || r == "" {
			continue
		}
		r = strings.Split(r, "#")[0] // possible comment at the end of the line
		r = strings.TrimSpace(r)
		parts := strings.Split(r, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("unable to parse location rule '%s", r)
		}
		place := strings.ToLower(parts[0])                // Place type like "continent", "country" or "city"
		value, err := strconv.ParseUint(parts[1], 10, 64) // GeoNames ID
		if err != nil {
			return nil, fmt.Errorf("unable to parse geoname id in rule '%s': %w", r, err)
		}
		switch place {
		case "continent", "country", "city":
			key := fmt.Sprintf("%s:%d", place, value)
			db[key] = struct{}{}
		default:
			return nil, fmt.Errorf("unable to parse location '%s' in rule '%s'; must be 'continent', 'country', or 'city'", place, r)
		}
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
			GeoNameID uint `maxminddb:"geoname_id"`
		} `maxminddb:"continent"`
		Country struct {
			GeoNameID uint `maxminddb:"geoname_id"`
		} `maxminddb:"country"`
		City struct {
			GeoNameID uint `maxminddb:"geoname_id"`
		} `maxminddb:"city"`
	}

	if err := m.geoDB.Lookup(ip, &record); err != nil {
		Log.WithField("ip", ip).WithError(err).Error("failed to lookup ip in geo location database")
		return "", false
	}
	keys := []string{
		fmt.Sprintf("continent:%d", record.Continent.GeoNameID),
		fmt.Sprintf("country:%d", record.Country.GeoNameID),
		fmt.Sprintf("city:%d", record.City.GeoNameID),
	}

	for _, key := range keys {
		if _, ok := m.db[key]; ok {
			return key, true
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
