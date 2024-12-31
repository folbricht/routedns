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

	mu        sync.RWMutex
	currWinID int64
	counters  map[string]*uint
	metrics   *RateLimiterMetrics
}

var _ Resolver = &RateLimiter{}

type RateLimiterOptions struct {
	Requests      uint     // Number of requests allwed per time period
	Window        uint     // Time period in seconds
	Prefix4       uint8    // Netmask to identify IP4 clients
	Prefix6       uint8    // Netmask to identify IP6 clients
	LimitResolver Resolver // Alternate resolver for rate-limited requests
}

type RateLimiterMetrics struct {
	// Count of queries.
	query *expvar.Int
	// Count of queries that have exceeded the rate limit.
	exceed *expvar.Int
	// Count of dropped queries.
	drop *expvar.Int
}

// NewRateLimiterIP returns a new instance of a query rate limiter.
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
		metrics: &RateLimiterMetrics{
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
	source := ci.SourceIP
	if ip4 := source.To4(); len(ip4) == net.IPv4len {
		source = source.Mask(net.CIDRMask(int(r.Prefix4), 32))
	} else {
		source = source.Mask(net.CIDRMask(int(r.Prefix6), 128))
	}
	key := source.String()

	// Calculate the current (fixed) window
	windowID := time.Now().Unix() / int64(r.Window)

	var reject bool
	r.mu.Lock()

	// If we have moved on to the next window, re-initialize the counters
	if windowID != r.currWinID {
		r.currWinID = windowID
		r.counters = make(map[string]*uint)
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
			log.With("resolver", r.LimitResolver).Debug("rate-limit exceeded, forwarding to limit-resolver")
			return r.LimitResolver.Resolve(q, ci)
		}
		r.metrics.drop.Add(1)
		log.Debug("rate-limit reached, dropping")
		return nil, nil
	}
	log.With("resolver", r.resolver).Debug("forwarding query to resolver")
	return r.resolver.Resolve(q, ci)
}

func (r *RateLimiter) String() string {
	return r.id
}
