package rdns

import (
	"errors"
	"expvar"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/miekg/dns"
)

const (
	defaultLoadBalanceInitialRTT       = 100 * time.Millisecond
	defaultLoadBalanceMinimumRTTSample = time.Microsecond
	defaultLoadBalanceEMAAlpha         = 0.1
	// Two transient failures in a row are unlikely to be coincidental; apply the
	// penalty only then to avoid suppressing a resolver that had a single slow response.
	loadBalancePenaltyThreshold = 2
	// Fraction of picks made uniformly at random instead of by weight. Exploration
	// keeps every resolver's stats fresh, guarantees a minimum traffic share so that
	// penalized or slow resolvers can recover (and be re-measured) rather than being
	// starved indefinitely, and avoids cold-start lock-in onto whichever resolver
	// happened to be probed first.
	defaultLoadBalanceExploration = 0.05
	// Floor for the EMA used when computing weights. Without it a resolver that
	// responds in microseconds would get a weight thousands of times the neutral
	// weight, starving slower or unprobed resolvers. Clamping to 1ms caps the
	// maximum weight at 100 (vs. the neutral 1.0).
	defaultLoadBalanceMinimumWeightRTT = time.Millisecond
)

// LoadBalance is a resolver group that prefers resolvers with lower average
// response times and penalizes resolvers that fail.
type LoadBalance struct {
	id        string
	resolvers []Resolver
	mu        sync.RWMutex
	stats     []loadBalanceStats
	opt       LoadBalanceOptions
	metrics   *FailRouterMetrics
	// Per-resolver current rttEMA in microseconds, published under
	// routedns.router.<id>.rtt keyed by resolver String().
	rttVars   []*expvar.Float
	randFloat func() float64
}

type loadBalanceStats struct {
	rttEMA      float64 // exponential moving average in microseconds
	count       int
	consecFails atomic.Int32 // reset to 0 on success; never read under mu
}

// LoadBalanceOptions contain settings for the load-balancing resolver group.
type LoadBalanceOptions struct {
	// Duration recorded as the RTT penalty for persistently failing resolvers
	// (after loadBalancePenaltyThreshold consecutive failures). 0 disables the
	// penalty; without it fast-failing resolvers are still prevented from
	// gaining weight via the upward-only EMA update on failure.
	FailurePenalty time.Duration

	// Determines if a SERVFAIL returned by a resolver should be considered an
	// error response and trigger a failover.
	ServfailError bool

	// Determines if an empty response returned by a resolver should be considered an
	// error response and trigger a failover.
	EmptyError bool
}

var _ Resolver = &LoadBalance{}

// NewLoadBalance returns a new instance of a load-balancing resolver group.
func NewLoadBalance(id string, opt LoadBalanceOptions, resolvers ...Resolver) *LoadBalance {
	rtt := getVarMap("router", id, "rtt")
	rttVars := make([]*expvar.Float, len(resolvers))
	for i, resolver := range resolvers {
		rttVars[i] = new(expvar.Float)
		rtt.Set(resolver.String(), rttVars[i])
	}
	return &LoadBalance{
		id:        id,
		resolvers: resolvers,
		stats:     make([]loadBalanceStats, len(resolvers)),
		opt:       opt,
		metrics:   NewFailRouterMetrics(id, len(resolvers)),
		rttVars:   rttVars,
		randFloat: rand.Float64,
	}
}

// Resolve a DNS query using a weighted random resolver selection. Resolvers with
// lower average response times receive more traffic. Failed resolvers are
// penalized and the request is retried with another resolver.
func (r *LoadBalance) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)
	var buf [8]int
	var remaining []int
	if len(r.resolvers) <= len(buf) {
		remaining = buf[:len(r.resolvers)]
	} else {
		remaining = make([]int, len(r.resolvers))
	}
	for i := range r.resolvers {
		remaining[i] = i
	}

	var (
		a   *dns.Msg
		err error
	)
	for len(remaining) > 0 {
		pos := r.pick(remaining)
		idx := remaining[pos]
		resolver := r.resolvers[idx]

		r.metrics.route.Add(resolver.String(), 1)
		log.With("resolver", resolver.String()).Debug("forwarding query to resolver")

		start := time.Now()
		a, err = resolver.Resolve(q.Copy(), ci)
		elapsed := time.Since(start)
		if err == nil && r.isSuccessResponse(a) {
			r.updateOnSuccess(idx, elapsed)
			return a, nil
		}

		log.With("resolver", resolver.String()).Debug("resolver returned failure",
			"error", err)
		r.metrics.failure.Add(resolver.String(), 1)
		// Only count a failover when there is another resolver to fall back to;
		// the last resolver failing is the end of the request, not a failover.
		if len(remaining) > 1 {
			r.metrics.failover.Add(1)
		}
		penalized := r.updateOnFailure(idx, elapsed)
		if penalized {
			Log.Debug("penalizing resolver", slog.Group("details",
				slog.String("group", r.id),
				slog.String("resolver", resolver.String()),
				slog.Duration("penalty", r.opt.FailurePenalty),
			))
		}

		remaining[pos] = remaining[len(remaining)-1]
		remaining = remaining[:len(remaining)-1]
	}
	if err == nil && a == nil {
		err = errors.New("no active resolvers left")
	}
	return a, err
}

func (r *LoadBalance) String() string {
	return r.id
}

// pick selects an index into remaining using weights derived from the inverse
// EMA response time. Resolvers without history use a neutral weight. With
// probability defaultLoadBalanceExploration a uniform random resolver is picked
// instead, ensuring every resolver keeps receiving some traffic.
func (r *LoadBalance) pick(remaining []int) int {
	// ε-greedy exploration: occasionally pick uniformly at random regardless of
	// weight so penalized/slow resolvers get re-measured and can recover.
	if r.randFloat() < defaultLoadBalanceExploration {
		return int(r.randFloat() * float64(len(remaining)))
	}

	var buf [8]float64
	var weights []float64
	if len(remaining) <= len(buf) {
		weights = buf[:len(remaining)]
	} else {
		weights = make([]float64, len(remaining))
	}

	minWeightRTT := float64(defaultLoadBalanceMinimumWeightRTT.Microseconds())
	r.mu.RLock()
	var total float64
	for i, idx := range remaining {
		weight := 1.0
		s := &r.stats[idx]
		if s.count > 0 && s.rttEMA > 0 {
			// Floor the effective RTT at weighting time only; rttEMA itself is
			// left unchanged so recovery and metrics still see the true value.
			weight = float64(defaultLoadBalanceInitialRTT.Microseconds()) / max(s.rttEMA, minWeightRTT)
		}
		weights[i] = weight
		total += weight
	}
	r.mu.RUnlock()

	selected := r.randFloat() * total
	for i, weight := range weights {
		selected -= weight
		if selected <= 0 {
			return i
		}
	}
	return len(remaining) - 1
}

// updateOnSuccess records a successful response time and clears the failure streak.
func (r *LoadBalance) updateOnSuccess(idx int, d time.Duration) {
	if d < defaultLoadBalanceMinimumRTTSample {
		d = defaultLoadBalanceMinimumRTTSample
	}
	us := float64(d.Microseconds())
	// Swap so the read-and-reset of the failure streak is a single atomic op.
	wasPenalized := r.stats[idx].consecFails.Swap(0) >= loadBalancePenaltyThreshold
	r.mu.Lock()
	s := &r.stats[idx]
	switch {
	case s.count == 0:
		s.rttEMA = us
	case wasPenalized:
		// The EMA was inflated by the failure penalty; blending with alpha would
		// take ~20+ successes to decay back, during which the resolver gets little
		// traffic. Re-seed directly to the measured RTT so recovery is immediate.
		s.rttEMA = us
	default:
		s.rttEMA = defaultLoadBalanceEMAAlpha*us + (1-defaultLoadBalanceEMAAlpha)*s.rttEMA
	}
	ema := s.rttEMA
	s.count++
	r.mu.Unlock()
	r.rttVars[idx].Set(ema)
}

// updateOnFailure records a failed response time and returns true if the
// failure-penalty was applied (consecutive failure threshold reached).
//
// Without a penalty, only allow the EMA to move upward on failure. This
// prevents fast-failing resolvers (e.g. connection refused, returning in
// microseconds) from appearing artificially fast and attracting more traffic.
func (r *LoadBalance) updateOnFailure(idx int, elapsed time.Duration) bool {
	fails := r.stats[idx].consecFails.Add(1)
	penalize := r.opt.FailurePenalty > 0 && fails >= loadBalancePenaltyThreshold
	d := elapsed
	if penalize {
		d = r.opt.FailurePenalty
	}
	if d < defaultLoadBalanceMinimumRTTSample {
		d = defaultLoadBalanceMinimumRTTSample
	}
	us := float64(d.Microseconds())
	r.mu.Lock()
	s := &r.stats[idx]
	if s.count == 0 {
		// Seed with at least the baseline RTT so a fast first failure doesn't
		// give this resolver a large weight advantage over unprobed resolvers.
		s.rttEMA = max(us, float64(defaultLoadBalanceInitialRTT.Microseconds()))
	} else {
		newEMA := defaultLoadBalanceEMAAlpha*us + (1-defaultLoadBalanceEMAAlpha)*s.rttEMA
		if penalize || newEMA > s.rttEMA {
			s.rttEMA = newEMA
		}
	}
	ema := s.rttEMA
	s.count++
	r.mu.Unlock()
	r.rttVars[idx].Set(ema)
	return penalize
}

func (r *LoadBalance) isSuccessResponse(a *dns.Msg) bool {
	return isSuccessResponse(a, r.opt.ServfailError, r.opt.EmptyError)
}
