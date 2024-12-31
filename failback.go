package rdns

import (
	"expvar"
	"sync"
	"time"

	"log/slog"

	"github.com/miekg/dns"
)

// FailBack is a resolver group that queries the same resolver unless that
// returns a failure in which case the request is retried on the next one for
// up to N times (with N the number of resolvers in the group). If the last
// resolver fails, the first one in the list becomes the active one. After the
// reset timer expired without any further failures, the first resolver becomes
// active again. This group prefers the resolvers in the order they were added
// but fails over as necessary with regular retry of the higher-priority ones.
type FailBack struct {
	id        string
	resolvers []Resolver
	mu        sync.RWMutex
	failCh    chan struct{} // signal the timer to reset on failure
	active    int
	opt       FailBackOptions
	metrics   *FailRouterMetrics
}

// FailBackOptions contain group-specific options.
type FailBackOptions struct {
	// Switch back to the first resolver in the group after no further failures
	// for this amount of time. Default 1 minute.
	ResetAfter time.Duration

	// Determines if a SERVFAIL returned by a resolver should be considered an
	// error response and trigger a failover.
	ServfailError bool
}

var _ Resolver = &FailBack{}

type FailRouterMetrics struct {
	RouterMetrics
	// Failover count
	failover *expvar.Int
}

func NewFailRouterMetrics(id string, available int) *FailRouterMetrics {
	avail := getVarInt("router", id, "available")
	avail.Set(int64(available))
	return &FailRouterMetrics{
		RouterMetrics: RouterMetrics{
			route:     getVarMap("router", id, "route"),
			failure:   getVarMap("router", id, "failure"),
			available: avail,
		},
		failover: getVarInt("router", id, "failover"),
	}
}

// NewFailBack returns a new instance of a failover resolver group.
func NewFailBack(id string, opt FailBackOptions, resolvers ...Resolver) *FailBack {
	if opt.ResetAfter == 0 {
		opt.ResetAfter = time.Minute
	}
	return &FailBack{
		id:        id,
		resolvers: resolvers,
		opt:       opt,
		metrics:   NewFailRouterMetrics(id, len(resolvers)),
	}
}

// Resolve a DNS query using a failover resolver group that switches to the next
// resolver on error.
func (r *FailBack) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)
	var (
		err error
		a   *dns.Msg
	)
	for i := 0; i < len(r.resolvers); i++ {
		resolver, active := r.current()
		log.With("resolver", resolver.String()).Debug("forwarding query to resolver")
		r.metrics.route.Add(resolver.String(), 1)
		a, err = resolver.Resolve(q, ci)
		if err == nil && r.isSuccessResponse(a) { // Return immediately if successful
			return a, err
		}
		log.With("resolver", resolver.String()).Debug("resolver returned failure",
			"error", err)
		r.metrics.failure.Add(resolver.String(), 1)

		r.errorFrom(active)
	}
	return a, err
}

func (r *FailBack) String() string {
	return r.id
}

// Thread-safe method to return the currently active resolver.
func (r *FailBack) current() (Resolver, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resolvers[r.active], r.active
}

// Fail over to the next available resolver after receiving an error from i (the active). We
// need i to know which store returned the error as there could be failures from concurrent
// requests. Another request could have initiated the failover already. So ignore if i is not
// (no longer) the active store.
func (r *FailBack) errorFrom(i int) {
	r.mu.Lock()
	if i != r.active {
		r.mu.Unlock()
		return
	}
	if r.failCh == nil { // lazy start the reset timer
		r.failCh = r.startResetTimer()
	}
	r.active = (r.active + 1) % len(r.resolvers)
	Log.Debug("failing over to resolver", slog.Group("details", slog.String("id", r.id), slog.String("resolver", r.resolvers[r.active].String())))
	r.mu.Unlock()
	r.metrics.failover.Add(1)
	r.metrics.available.Add(-1)
	r.failCh <- struct{}{} // signal the timer to wait some more before switching back
}

// Set active=0 regularly after the reset timer has expired without further failures. Any failure,
// as signalled by the channel resets the timer again.
func (r *FailBack) startResetTimer() chan struct{} {
	failCh := make(chan struct{}, 1)
	go func() {
		timer := time.NewTimer(r.opt.ResetAfter)
		for {
			select {
			case <-failCh:
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
				r.mu.Lock()
				r.active = 0
				Log.Debug("failing back to resolver", slog.Group("details", slog.String("resolver", r.resolvers[r.active].String())))
				r.mu.Unlock()
				r.metrics.available.Add(1)
				// we just reset to the first resolver, let's wait for another failure before running again
				<-failCh
			}
			timer.Reset(r.opt.ResetAfter)
		}
	}()
	return failCh
}

// Returns true is the response is considered successful given the options.
func (r *FailBack) isSuccessResponse(a *dns.Msg) bool {
	return a == nil || !(r.opt.ServfailError && a.Rcode == dns.RcodeServerFailure)
}
