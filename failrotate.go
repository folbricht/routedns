package rdns

import (
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// FailRotate is a resolver group that queries the same resolver unless that
// returns a failure in which case the request is retried on the next one for
// up to N times (with N the number of resolvers in the group). If the last
// resolver fails, the first one in the list becomes the active one. This
// group does not fail back automatically.
type FailRotate struct {
	id        string
	resolvers []Resolver
	mu        sync.RWMutex
	active    int
}

var _ Resolver = &FailRotate{}

// NewFailRotate returns a new instance of a failover resolver group.
func NewFailRotate(id string, resolvers ...Resolver) *FailRotate {
	return &FailRotate{id: id, resolvers: resolvers}
}

// Resolve a DNS query using a failover resolver group that switches to the next
// resolver on error.
func (r *FailRotate) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := Log.WithFields(logrus.Fields{"id": r.id, "client": ci.SourceIP, "qname": qName(q)})
	var gErr error
	for i := 0; i < len(r.resolvers); i++ {
		resolver, active := r.current()
		log.WithField("resolver", resolver.String()).Trace("forwarding query to resolver")
		a, err := resolver.Resolve(q, ci)
		if err == nil { // Return immediately if successful
			return a, err
		}
		log.WithField("resolver", resolver.String()).WithError(err).Debug("resolver returned failure")

		// Record the error to be returned when all requests fail
		gErr = err

		r.errorFrom(active)
	}
	return nil, gErr
}

func (r *FailRotate) String() string {
	return r.id
}

// Thread-safe method to return the currently active resolver.
func (r *FailRotate) current() (Resolver, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.resolvers[r.active], r.active
}

// Fail over to the next available resolver after recveiving an error from i (the active). We
// need i to know which store returned the error as there could be failures from concurrent
// requests. Another request could have initiated the failover already. So ignore if i is not
// (no longer) the active store.
func (r *FailRotate) errorFrom(i int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i != r.active {
		return
	}
	r.active = (r.active + 1) % len(r.resolvers)
	Log.WithFields(logrus.Fields{
		"id":       r.id,
		"resolver": r.resolvers[r.active].String(),
	}).Debug("failing over to resolver")
}
