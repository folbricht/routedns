package rdns

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Random is a resolver group that randomly picks a resolver from it's list
// of resolvers. If one resolver fails, it is removed from the list of active
// resolvers for a period of time and the query retried.
type Random struct {
	id        string
	resolvers []Resolver
	mu        sync.RWMutex
	opt       RandomOptions
	metrics   *FailRouterMetrics
}

var _ Resolver = &Random{}

// RandomOptions contain settings for the random resolver group.
type RandomOptions struct {
	// Re-enable resolvers after this time after a failure
	ResetAfter time.Duration

	// Determines if a SERVFAIL returned by a resolver should be considered an
	// error response and cause the resolver to be removed from the group temporarily.
	ServfailError bool
}

// NewRandom returns a new instance of a random resolver group.
func NewRandom(id string, opt RandomOptions, resolvers ...Resolver) *Random {
	rand.Seed(time.Now().UnixNano())
	if opt.ResetAfter == 0 {
		opt.ResetAfter = time.Minute
	}
	return &Random{
		id:        id,
		resolvers: resolvers,
		opt:       opt,
		metrics:   NewFailRouterMetrics(id, len(resolvers)),
	}
}

// Resolve a DNS query using a random resolver.
func (r *Random) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)
	for {
		resolver := r.pick()
		if resolver == nil {
			log.Warn("no active resolvers left")
			return nil, errors.New("no active resolvers left")
		}

		r.metrics.route.Add(resolver.String(), 1)
		log.With("resolver", resolver.String()).Debug("forwarding query to resolver")
		a, err := resolver.Resolve(q, ci)
		if err == nil && r.isSuccessResponse(a) { // Return immediately if successful
			return a, err
		}
		log.With("resolver", resolver.String()).Debug("resolver returned failure",
			"error", err)
		r.metrics.failure.Add(resolver.String(), 1)
		r.deactivate(resolver)
	}
}

func (r *Random) String() string {
	return r.id
}

// Pick a random resolver from the list of active ones.
func (r *Random) pick() Resolver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	available := len(r.resolvers)
	r.metrics.available.Set(int64(available))
	r.metrics.failover.Add(1)
	if available == 0 {
		return nil
	}
	return r.resolvers[rand.Intn(available)]
}

// Remove the resolver from the list of active ones and schedule it to
// come back in again later.
func (r *Random) deactivate(bad Resolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	filtered := make([]Resolver, 0, len(r.resolvers))
	for _, resolver := range r.resolvers {
		if resolver == bad {
			Log.Debug("de-activating resolver",
				"id", r.id,
				"resolver", bad.String(),
			)
			go r.reactivateLater(bad)
			continue
		}
		filtered = append(filtered, resolver)
	}
	r.resolvers = filtered
}

// Bring back a failed resolver after some time.
func (r *Random) reactivateLater(resolver Resolver) {
	time.Sleep(r.opt.ResetAfter)
	r.mu.Lock()
	defer r.mu.Unlock()
	Log.Debug("re-activating resolver",
		"id", r.id,
		"resolver", resolver.String(),
	)
	r.resolvers = append(r.resolvers, resolver)
	r.metrics.available.Set(int64(len(r.resolvers)))
}

// Returns true is the response is considered successful given the options.
func (r *Random) isSuccessResponse(a *dns.Msg) bool {
	return a == nil || !(r.opt.ServfailError && a.Rcode == dns.RcodeServerFailure)
}
