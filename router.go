package rdns

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// Router for DNS requests based on query type and/or name. Implements the Resolver interface.
type Router struct {
	routes []*route
}

var _ Resolver = &Router{}

// NewRouter returns a new router instance. The router won't have any routes and can only be used
// once Add() is called to setup a route.
func NewRouter() *Router {
	return new(Router)
}

// Resolve a request by routing it to the right resolved based on the routes setup in the router.
func (r *Router) Resolve(q *dns.Msg) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	question := q.Question[0]
	for _, route := range r.routes {
		if route.typ != 0 && route.typ != question.Qtype {
			continue
		}
		if !route.name.MatchString(question.Name) {
			continue
		}
		Log.Printf("routing query for '%s' to %s", qName(q), route.resolver)
		return route.resolver.Resolve(q)
	}
	return nil, fmt.Errorf("no route for %s", question.String())
}

// Add a new route to the router. New routes are appended to the existing
// ones and are evaluated in the same order they're added. The default
// route (no name, no type) should be added last since subsequently added
// routes won't have any impact.
func (r *Router) Add(name, typ string, resolver Resolver) error {
	t, err := stringToType(typ)
	if err != nil {
		return err
	}
	re, err := regexp.Compile(name)
	if err != nil {
		return err
	}
	newRoute := &route{
		typ:      t,
		name:     re,
		resolver: resolver,
	}

	r.routes = append(r.routes, newRoute)
	return nil
}

func (r *Router) String() string {
	var rs []string
	for _, route := range r.routes {
		rs = append(rs, route.String())
	}
	return fmt.Sprintf("Router(%s)", strings.Join(rs, ";"))
}

// Convert DNS type strings into the numberical type, for example "A" -> 1.
func stringToType(s string) (uint16, error) {
	if s == "" {
		return 0, nil
	}
	for k, v := range dns.TypeToString {
		if v == s {
			return k, nil
		}
	}
	return 0, fmt.Errorf("unknown type '%s", s)
}

type route struct {
	typ      uint16
	name     *regexp.Regexp
	resolver Resolver
}

func (r route) String() string {
	if r.isDefault() {
		return fmt.Sprintf("default->%s", r.resolver)
	}
	return fmt.Sprintf("%s:%s->%s", r.name, dns.Type(r.typ), r.resolver)
}

func (r route) isDefault() bool {
	return r.typ == 0 && r.name.String() == ""
}
