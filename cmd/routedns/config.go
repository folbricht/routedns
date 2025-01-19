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
	IPVersion  int `toml:"ip-version"` // 4 = IPv4, 6 = IPv6
	Transport  string
	Resolver   string
	CA         string
	ServerKey  string   `toml:"server-key"`
	ServerCrt  string   `toml:"server-crt"`
	MutualTLS  bool     `toml:"mutual-tls"`
	NoTLS      bool     `toml:"no-tls"` // Disable TLS in DoH servers
	AllowedNet []string `toml:"allowed-net"`
	KeySeed    string   `toml:"key-seed"`  // ODoH HPKE key seed, 16 byte hex key. Generate for example with: "openssl rand -hex 16"
	OdohMode   string   `toml:"odoh-mode"` // ODoH mode - accepts "proxy", "target" or "dual", default is target mode
	AllowDoH   bool     `toml:"allow-doh"` // Allow ODoH listeners to also handle DoH queries to /dns-query
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
	QueryTimeout  int    `toml:"query-timeout"`  // Query timeout in seconds

	// Proxy configuration
	Socks5Address      string `toml:"socks5-address"`
	Socks5Username     string `toml:"socks5-username"`
	Socks5Password     string `toml:"socks5-password"`
	Socks5ResolveLocal bool   `toml:"socks5-resolve-local"` // Resolve DNS server address locally (i.e. bootstrap-resolver), not on the SOCK5 proxy

	//QUIC and DoH/3 configuration
	Use0RTT bool `toml:"enable-0rtt"`

	// URL for Oblivious DNS target
	Target       string `toml:"target"`
	TargetConfig string `toml:"target-config"`
}

// DoH-specific resolver options
type doh struct {
	Method string
}

// Cache backend options
type cacheBackend struct {
	Type                 string // Cache backend type.Defaults to "memory"
	Size                 int    // Max number of items to keep in the cache. Default 0 == unlimited. Deprecated, use backend
	GCPeriod             int    `toml:"gc-period"` // Time-period (seconds) used to expire cached items
	Filename             string // File to load/store cache content, optional, for "memory" type cache
	SaveInterval         int    `toml:"save-interval"`           // Seconds to write the cache to file
	RedisNetwork         string `toml:"redis-network"`           // The network type, either tcp or unix. Defaults to tcp.
	RedisAddress         string `toml:"redis-address"`           // Address for redis cache
	RedisUsername        string `toml:"redis-username"`          // Redis username
	RedisPassword        string `toml:"redis-password"`          // Redis password
	RedisDB              int    `toml:"redis-db"`                // Redis database to be selected after connecting to the server
	RedisKeyPrefix       string `toml:"redis-key-prefix"`        // Prefix any cache entry
	RedisMaxRetries      int    `toml:"redis-max-retries"`       // Maximum number of retries before giving up. Default is 3 retries; -1 (not 0) disables retries.
	RedisMinRetryBackoff int    `toml:"redis-min-retry-backoff"` // Minimum back-off between each retry. Default is 8 milliseconds; -1 disables back-off.
	RedisMaxRetryBackoff int    `toml:"redis-max-retry-backoff"` // Maximum back-off between each retry. Default is 512 milliseconds; -1 disables back-off.
}

type group struct {
	Resolvers  []string
	Type       string
	Replace    []rdns.ReplaceOperation // only used by "replace" type
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
	Backend                  *cacheBackend
	GCPeriod                 int               `toml:"gc-period"`                   // Time-period (seconds) used to expire cached items in the "cache" type. Deprecated, use backend
	CacheSize                int               `toml:"cache-size"`                  // Max number of items to keep in the cache. Default 0 == unlimited. Deprecated, use backend
	CacheNegativeTTL         uint32            `toml:"cache-negative-ttl"`          // TTL to apply to negative responses, default 60.
	CacheAnswerShuffle       string            `toml:"cache-answer-shuffle"`        // Algorithm to use for modifying the response order of cached items
	CacheHardenBelowNXDOMAIN bool              `toml:"cache-harden-below-nxdomain"` // Return NXDOMAIN if an NXDOMAIN is cached for a parent domain
	CacheFlushQuery          string            `toml:"cache-flush-query"`           // Flush the cache when a query for this name is received
	PrefetchTrigger          uint32            `toml:"cache-prefetch-trigger"`      // Prefetch when the TTL of a query has fallen below this value
	PrefetchEligible         uint32            `toml:"cache-prefetch-eligible"`     // Only records with TTL greater than this are considered for prefetch
	CacheRcodeMaxTTL         map[string]uint32 `toml:"cache-rcode-max-ttl"`         // Rcode specific max TTL to keep in the cache

	// Blocklist options
	Blocklist []string // Blocklist rules, only used by "blocklist" type
	Format    string   // Blocklist input format: "regex", "domain", "hosts", or "mac"
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
	Inverted          bool     // Only allow IPs on the blocklist. Supported in response-blocklist-ip and response-blocklist-name
	UseECS            bool     `toml:"use-ecs"` // Use ECS IP address in client-blocklist

	// Static responder options
	Answer   []string
	NS       []string
	Extra    []string
	RCode    int
	EDNS0EDE struct {
		Code uint16 `toml:"code"` // Code defined in https://datatracker.ietf.org/doc/html/rfc8914
		Text string `toml:"text"` // Extra text containing additional information
	} `toml:"edns0-ede"` // Extended DNS Errors
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

	// Query logging options
	OutputFile   string `toml:"output-file"`   // Log filename or blank for STDOUT
	OutputFormat string `toml:"output-format"` // "text" or "json"
}

// Block/Allowlist items for blocklist-v2
type list struct {
	Name         string
	Format       string
	Source       string
	CacheDir     string `toml:"cache-dir"`     // Where to store copies of remote blocklists for faster startup
	AllowFailure bool   `toml:"allow-failure"` // Don't fail on error and keep using the prior ruleset
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
