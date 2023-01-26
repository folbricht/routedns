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
	Title             string
	BootstrapResolver resolver `toml:"bootstrap-resolver"`
	Listeners         map[string]listener
	Resolvers         map[string]resolver
	Groups            map[string]group
	Routers           map[string]router
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
	NoTLS      bool     `toml:"no-tls"` // Disable TLS in DoH servers
	AllowedNet []string `toml:"allowed-net"`
	Frontend   dohFrontend
}

// DoH listener frontend options
type dohFrontend struct {
	HTTPProxyNet string `toml:"trusted-proxy"`
}

type resolver struct {
	Address       string
	Protocol      string
	Transport     string
	DoH           doh
	CA            string
	ClientKey     string `toml:"client-key"`
	ClientCrt     string `toml:"client-crt"`
	ServerName    string `toml:"server-name"` // TLS server name presented in the server certificate
	BootstrapAddr string `toml:"bootstrap-address"`
	LocalAddr     string `toml:"local-address"`
	EDNS0UDPSize  uint16 `toml:"edns0-udp-size"` // UDP resolver option
}

// DoH-specific resolver options
type doh struct {
	Method string
}

type group struct {
	Resolvers  []string
	Type       string
	Replace    []rdns.ReplaceOperation // only used by "replace" type
	GCPeriod   int                     `toml:"gc-period"`   // Time-period (seconds) used to expire cached items in the "cache" type
	ECSOp      string                  `toml:"ecs-op"`      // ECS modifier operation, "add", "delete", "privacy"
	ECSAddress net.IP                  `toml:"ecs-address"` // ECS address. If empty for "add", uses the client IP. Ignored for "privacy" and "delete"
	ECSPrefix4 uint8                   `toml:"ecs-prefix4"` // ECS IPv4 address prefix, 0-32. Used for "add" and "privacy"
	ECSPrefix6 uint8                   `toml:"ecs-prefix6"` // ECS IPv6 address prefix, 0-128. Used for "add" and "privacy"
	TTLMin     uint32                  `toml:"ttl-min"`     // TTL minimum to apply to responses in the TTL-modifier
	TTLMax     uint32                  `toml:"ttl-max"`     // TTL maximum to apply to responses in the TTL-modifier
	TTLSelect  string                  `toml:"ttl-select"`  // Modifier selection function, "lowest", "highest", "average", "first", "last", "random"
	EDNS0Op    string                  `toml:"edns0-op"`    // EDNS0 modifier operation, "add" or "delete"
	EDNS0Code  uint16                  `toml:"edns0-code"`  // EDNS0 modifier option code
	EDNS0Data  []byte                  `toml:"edns0-data"`  // EDNS0 modifier option data

	// Failover/Failback options
	ResetAfter    int  `toml:"reset-after"`    // Time in seconds after which to reset resolvers in fail-back and random groups, default 60.
	ServfailError bool `toml:"servfail-error"` // If true, SERVFAIL responses are considered errors and cause failover etc.

	// Cache options
	CacheSize                int    `toml:"cache-size"`                  // Max number of items to keep in the cache. Default 0 == unlimited
	CacheNegativeTTL         uint32 `toml:"cache-negative-ttl"`          // TTL to apply to negative responses, default 60.
	CacheAnswerShuffle       string `toml:"cache-answer-shuffle"`        // Algorithm to use for modifying the response order of cached items
	CacheHardenBelowNXDOMAIN bool   `toml:"cache-harden-below-nxdomain"` // Return NXDOMAIN if an NXDOMAIN is cached for a parent domain
	CacheFlushQuery          string `toml:"cache-flush-query"`           // Flush the cache when a query for this name is received
	PrefetchTrigger          uint32 `toml:"cache-prefetch-trigger"`      // Prefetch when the TTL of a query has fallen below this value
	PrefetchEligible         uint32 `toml:"cache-prefetch-eligible"`     // Only records with TTL greater than this are considered for prefetch

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
	Answer   []string
	NS       []string
	Extra    []string
	RCode    int
	Truncate bool `toml:"truncate"` // When true, TC-Bit is set

	// Rate-limiting options
	Requests      uint   // Number of requests allowed
	Window        uint   // Time period in seconds for the requests
	Prefix4       uint8  // Prefix bits to identify IPv4 client
	Prefix6       uint8  // Prefix bits to identify IPv6 client
	LimitResolver string `toml:"limit-resolver"` // Resolver to use when rate-limit exceeded

	// Fastest-TCP probe options
	Port          int
	WaitAll       bool   `toml:"wait-all"`        // Wait for all probes to return and respond with a sorted list. Generally slower
	SuccessTTLMin uint32 `toml:"success-ttl-min"` // Set the TTL of records that were probed successfully

	// Response Collapse options
	NullRCode int `toml:"null-rcode"` // Response code if after collapsing, no answers are left

	// Truncate-Retry options
	RetryResolver string `toml:"retry-resolver"`

	// Syslog options
	Network     string `toml:"network"`  // "udp", "tcp", "unix"
	Address     string `toml:"address"`  // Endpoint address, defaults to local syslog server
	Priority    string `toml:"priority"` // Syslog priority, "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"
	Tag         string `toml:"tag"`
	LogRequest  bool   `toml:"log-request"`  // Logs request records to syslog
	LogResponse bool   `toml:"log-response"` // Logs response records to syslog
	Verbose     bool   `toml:"verbose"`      // When logging responses, include types that don't match the query type
}

// Block/Allowlist items for blocklist-v2
type list struct {
	Name     string
	Format   string
	Source   string
	CacheDir string `toml:"cache-dir"` // Where to store copies of remote blocklists for faster startup
}

type router struct {
	Routes []route
}

type route struct {
	Type          string // Deprecated, use "Types" instead
	Types         []string
	Class         string
	Name          string
	Source        string
	Weekdays      []string // 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'
	After, Before string   // Hour:Minute in 24h format, for example "14:30"
	Invert        bool     // Invert the result of the match
	DoHPath       string   `toml:"doh-path"` // DoH query path if received over DoH (regexp)
	Resolver      string
	Listener      string // ID of the listener that received the original request
	TLSServerName string `toml:"servername"` // TLS servername
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
