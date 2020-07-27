package main

import (
	"bytes"
	"io"
	"net"
	"os"

	"github.com/BurntSushi/toml"
	rdns "github.com/folbricht/routedns"
)

type config struct {
	Title     string
	Listeners map[string]listener
	Resolvers map[string]resolver
	Groups    map[string]group
	Routers   map[string]router
}

type listener struct {
	Address    string
	Protocol   string
	Transport  string
	Resolver   string
	CA         string
	ServerKey  string   `toml:"server-key"`
	ServerCrt  string   `toml:"server-crt"`
	MutualTLS  bool     `toml:"mutual-tls"`
	AllowedNet []string `toml:"allowed-net"`
	DoH        dohListener
}

// DoH-specific resolver options
type dohListener struct {
	HTTPProxyAddr string `toml:"trusted-proxy"`
}

type resolver struct {
	Address       string
	Protocol      string
	Transport     string
	DoH           doh
	CA            string
	ClientKey     string `toml:"client-key"`
	ClientCrt     string `toml:"client-crt"`
	BootstrapAddr string `toml:"bootstrap-address"`
	LocalAddr     string `toml:"local-address"`
}

// DoH-specific resolver options
type doh struct {
	Method string
}

type group struct {
	Resolvers        []string
	Type             string
	Replace          []rdns.ReplaceOperation // only used by "replace" type
	GCPeriod         int                     `toml:"gc-period"`          // Time-period (seconds) used to expire cached items in the "cache" type
	ECSOp            string                  `toml:"ecs-op"`             // ECS modifier operation, "add", "delete", "privacy"
	ECSAddress       net.IP                  `toml:"ecs-address"`        // ECS address. If empty for "add", uses the client IP. Ignored for "privacy" and "delete"
	ECSPrefix4       uint8                   `toml:"ecs-prefix4"`        // ECS IPv4 address prefix, 0-32. Used for "add" and "privacy"
	ECSPrefix6       uint8                   `toml:"ecs-prefix6"`        // ECS IPv6 address prefix, 0-128. Used for "add" and "privacy"
	CacheSize        int                     `toml:"cache-size"`         // Max number of items to keep in the cache. Default 0 == unlimited
	CacheNegativeTTL uint32                  `toml:"cache-negative-ttl"` // TTL to apply to negative responses, default 60.
	TTLMin           uint32                  `toml:"ttl-min"`            // TTL minimum to apply to responses in the TTL-modifier
	TTLMax           uint32                  `toml:"ttl-max"`            // TTL maximum to apply to responses in the TTL-modifier

	// Blocklist options
	Blocklist []string // Blocklist rules, only used by "blocklist" type
	Format    string   // Blocklist input format: "regex", "domain", or "hosts"
	Source    string   // Location of external blocklist, can be a local path or remote URL
	Refresh   int      // Blocklist refresh when using an external source, in seconds

	// Blocklist-v2 options
	Filter            bool     // Filter response records rather than return NXDOMAIN
	BlockListResolver string   `toml:"blocklist-resolver"`
	AllowListResolver string   `toml:"allowlist-resolver"`
	BlocklistFormat   string   `toml:"blocklist-format"` // only used for static blocklists in the config
	BlocklistSource   []list   `toml:"blocklist-source"`
	BlocklistRefresh  int      `toml:"blocklist-refresh"`
	Allowlist         []string // Rules to override the blocklist rules
	AllowlistFormat   string   `toml:"allowlist-format"` // only used for static allowlists in the config
	AllowlistSource   []list   `toml:"allowlist-source"`
	AllowlistRefresh  int      `toml:"allowlist-refresh"`
	LocationDB        string   `toml:"location-db"` // GeoIP database file for response blocklist. Default "/usr/share/GeoIP/GeoLite2-City.mmdb"

	// Static responder options
	Answer []string
	NS     []string
	Extra  []string
	RCode  int

	// Rate-limiting options
	Requests      uint   // Number of requests allowed
	Window        uint   // Time period in seconds for the requests
	Prefix4       uint8  // Prefix bits to identify IPv4 client
	Prefix6       uint8  // Prefix bits to identify IPv6 client
	LimitResolver string `toml:"limit-resolver"` // Resolver to use when rate-limit exceeded
}

// Block/Allowlist items for blocklist-v2
type list struct {
	Format string
	Source string
}

type router struct {
	Routes []route
}

type route struct {
	Type     string
	Class    string
	Name     string
	Source   string
	Resolver string
}

// LoadConfig reads a config file and returns the decoded structure.
func loadConfig(name ...string) (config, error) {
	b := new(bytes.Buffer)
	var c config
	for _, fn := range name {
		if err := loadFile(b, fn); err != nil {
			return c, err
		}
		b.WriteString("\n")
	}
	_, err := toml.DecodeReader(b, &c)
	return c, err
}

func loadFile(w io.Writer, name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func parseCIDRList(networks []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range networks {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return out, err
		}
		out = append(out, n)
	}
	return out, nil
}
