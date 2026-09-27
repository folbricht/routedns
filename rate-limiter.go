package rdns

import (
	"expvar"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RateLimiter is a resolver that limits the number of queries by a client (network)
// that are passed to the upstream resolver per timeframe.
type RateLimiter struct {
	id       string
	resolver Resolver
	RateLimiterOptions

	// The masks the prefix lengths describe, built once rather than per query.
	mask4, mask6 net.IPMask

	mu        sync.RWMutex
	currWinID int64
	counters  map[clientNetwork]*uint
	metrics   *rateLimiterMetrics
}

// clientNetwork identifies the network a query came from, the client address
// with the configured prefix applied. An array rather than a string so that
// using it as a map key costs no allocation; a v4 address sits in the first
// four bytes with the length saying so.
type clientNetwork struct {
	addr [net.IPv6len]byte
	len  uint8
}

var _ Resolver = &RateLimiter{}

type RateLimiterOptions struct {
	Requests      uint     // Number of requests allowed per time period
	Window        uint     // Time period in seconds
	Prefix4       uint8    // Netmask to identify IP4 clients
	Prefix6       uint8    // Netmask to identify IP6 clients
	LimitResolver Resolver // Alternate resolver for rate-limited requests
}

type rateLimiterMetrics struct {
	// Count of queries.
	query *expvar.Int
	// Count of queries that have exceeded the rate limit.
	exceed *expvar.Int
	// Count of dropped queries.
	drop *expvar.Int
}

// NewRateLimiter returns a new instance of a query rate limiter.
func NewRateLimiter(id string, resolver Resolver, opt RateLimiterOptions) *RateLimiter {
	if opt.Window == 0 {
		opt.Window = 60
	}
	if opt.Prefix4 == 0 {
		opt.Prefix4 = 24
	}
	if opt.Prefix6 == 0 {
		opt.Prefix6 = 56
	}
	return &RateLimiter{
		id:                 id,
		resolver:           resolver,
		RateLimiterOptions: opt,
		mask4:              net.CIDRMask(int(opt.Prefix4), 32),
		mask6:              net.CIDRMask(int(opt.Prefix6), 128),
		metrics: &rateLimiterMetrics{
			query:  getVarInt("router", id, "query"),
			exceed: getVarInt("router", id, "exceed"),
			drop:   getVarInt("router", id, "drop"),
		},
	}
}

// Resolve a DNS query while limiting the query rate per time period.
func (r *RateLimiter) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)
	r.metrics.query.Add(1)

	// Apply the desired mask to the client IP to build a key it identify the client (network)
	key := r.clientKey(ci.SourceIP)

	// Calculate the current (fixed) window
	windowID := time.Now().Unix() / int64(r.Window)

	var reject bool
	r.mu.Lock()

	// If we have moved on to the next window, re-initialize the counters
	if windowID != r.currWinID {
		r.currWinID = windowID
		r.counters = make(map[clientNetwork]*uint)
	}

	// Load the current counter for this client or make a new one
	v, ok := r.counters[key]
	if !ok {
		v = new(uint)
		r.counters[key] = v
	}

	// Check the number of requests made in this window
	if *v >= r.Requests {
		reject = true
	}
	*v++
	r.mu.Unlock()

	if reject {
		r.metrics.exceed.Add(1)
		if r.LimitResolver != nil {
			log.Debug("rate-limit exceeded, forwarding to limit-resolver", "resolver", r.LimitResolver)
			return r.LimitResolver.Resolve(q, ci)
		}
		r.metrics.drop.Add(1)
		log.Debug("rate-limit reached, dropping")
		return nil, nil
	}
	log.Debug("forwarding query to resolver", "resolver", r.resolver)
	return r.resolver.Resolve(q, ci)
}

// clientKey masks a client address down to the network the limit counts, in a
// form that can be a map key without allocating.
func (r *RateLimiter) clientKey(ip net.IP) clientNetwork {
	var k clientNetwork
	if ip4 := ip.To4(); len(ip4) == net.IPv4len {
		k.len = net.IPv4len
		for i := range ip4 {
			k.addr[i] = ip4[i] & r.mask4[i]
		}
		return k
	}
	ip16 := ip.To16()
	if ip16 == nil { // not an address at all, all such queries share a counter
		return k
	}
	k.len = net.IPv6len
	for i := range ip16 {
		k.addr[i] = ip16[i] & r.mask6[i]
	}
	return k
}

func (r *RateLimiter) String() string {
	return r.id
}
