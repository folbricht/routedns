package rdns

import (
	"errors"
	"expvar"
	"fmt"

	"github.com/miekg/dns"
)

// Router for DNS requests based on query type and/or name. Implements the Resolver interface.
type Router struct {
	id      string
	routes  []*route
	metrics *RouterMetrics
}

var _ Resolver = &Router{}

type RouterMetrics struct {
	// Next route counts.
	route *expvar.Map
	// Next route failure counts.
	failure *expvar.Map
	// Count of available routes.
	available *expvar.Int
}

func NewRouterMetrics(id string, available int) *RouterMetrics {
	avail := getVarInt("router", id, "available")
	avail.Set(int64(available))
	return &RouterMetrics{
		route:     getVarMap("router", id, "route"),
		failure:   getVarMap("router", id, "failure"),
		available: avail,
	}
}

// NewRouter returns a new router instance. The router won't have any routes and can only be used
// once Add() is called to setup a route.
func NewRouter(id string) *Router {
	return &Router{
		id:      id,
		metrics: NewRouterMetrics(id, 0),
	}
}

// Resolve a request by routing it to the right resolved based on the routes setup in the router.
func (r *Router) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	question := q.Question[0]
	log := logger(r.id, q, ci)
	for _, route := range r.routes {
		if !route.match(q, ci) {
			continue
		}
		log.Debug("routing query to resolver",
			"route", route.String(),
			"resolver", route.resolver.String())
		r.metrics.route.Add(route.resolver.String(), 1)
		a, err := route.resolver.Resolve(q, ci)
		if err != nil {
			r.metrics.failure.Add(route.resolver.String(), 1)
		}
		return a, err
	}
	return nil, fmt.Errorf("no route for %s", question.String())
}

// Add a new route to the router. New routes are appended to the existing
// ones and are evaluated in the same order they're added. The default
// route (no name, no type) should be added last since subsequently added
// routes won't have any impact. Name is a regular expression that is
// applied to the name in the first question section of the DNS message.
// Source is an IP or network in CIDR format.
func (r *Router) Add(routes ...*route) {
	r.routes = append(r.routes, routes...)
	r.metrics.available.Add(1)
}

func (r *Router) String() string {
	return r.id
}
