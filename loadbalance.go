package rdns

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"log/slog"

	"github.com/miekg/dns"
)

const (
	defaultLoadBalanceInitialRTT       = 100 * time.Millisecond
	defaultLoadBalanceMinimumRTTSample = time.Microsecond
	defaultLoadBalanceEMAAlpha         = 0.1
	// consecutive failures required before the failure-penalty is applied.
	loadBalancePenaltyThreshold = 2
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
	randFloat func() float64
}

type loadBalanceStats struct {
	rttEMA      float64 // exponential moving average in microseconds
	count       int
	consecFails int // reset to 0 on success
}

// LoadBalanceOptions contain settings for the load-balancing resolver group.
type LoadBalanceOptions struct {
	// Duration used as the response-time penalty for failed lookups.
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
	return &LoadBalance{
		id:        id,
		resolvers: resolvers,
		stats:     make([]loadBalanceStats, len(resolvers)),
		opt:       opt,
		metrics:   NewFailRouterMetrics(id, len(resolvers)),
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
		a, err = resolver.Resolve(q, ci)
		elapsed := time.Since(start)
		if err == nil && r.isSuccessResponse(a) {
			r.updateRTT(idx, elapsed)
			r.resetFails(idx)
			return a, nil
		}

		log.With("resolver", resolver.String()).Debug("resolver returned failure",
			"error", err)
		r.metrics.failure.Add(resolver.String(), 1)
		r.metrics.failover.Add(1)
		if r.opt.FailurePenalty > 0 && r.incrementFails(idx) >= loadBalancePenaltyThreshold {
			Log.Info("penalizing resolver", slog.Group("details",
				slog.String("group", r.id),
				slog.String("resolver", resolver.String()),
				slog.Duration("penalty", r.opt.FailurePenalty),
			))
			r.updateRTT(idx, r.opt.FailurePenalty)
		} else {
			r.updateRTT(idx, elapsed)
		}

		remaining = append(remaining[:pos], remaining[pos+1:]...)
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
// EMA response time. Resolvers without history use a neutral weight.
func (r *LoadBalance) pick(remaining []int) int {
	var buf [8]float64
	var weights []float64
	if len(remaining) <= len(buf) {
		weights = buf[:len(remaining)]
	} else {
		weights = make([]float64, len(remaining))
	}

	r.mu.RLock()
	var total float64
	for i, idx := range remaining {
		weight := 1.0
		stat := r.stats[idx]
		if stat.count > 0 && stat.rttEMA > 0 {
			weight = float64(defaultLoadBalanceInitialRTT.Microseconds()) / stat.rttEMA
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

func (r *LoadBalance) updateRTT(idx int, d time.Duration) {
	if d < defaultLoadBalanceMinimumRTTSample {
		d = defaultLoadBalanceMinimumRTTSample
	}
	us := float64(d.Microseconds())
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.stats[idx]
	if s.count == 0 {
		s.rttEMA = us
	} else {
		s.rttEMA = defaultLoadBalanceEMAAlpha*us + (1-defaultLoadBalanceEMAAlpha)*s.rttEMA
	}
	s.count++
}

func (r *LoadBalance) incrementFails(idx int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats[idx].consecFails++
	return r.stats[idx].consecFails
}

func (r *LoadBalance) resetFails(idx int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats[idx].consecFails = 0
}

func (r *LoadBalance) isSuccessResponse(a *dns.Msg) bool {
	return isSuccessResponse(a, r.opt.ServfailError, r.opt.EmptyError)
}
