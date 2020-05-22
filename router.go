package rdns

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
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
func (r *Router) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	question := q.Question[0]
	log := Log.WithFields(logrus.Fields{"client": ci.SourceIP, "qname": question})
	for _, route := range r.routes {
		if route.typ != 0 && route.typ != question.Qtype {
			continue
		}
		if route.class != 0 && route.class != question.Qclass {
			continue
		}
		if !route.name.MatchString(question.Name) {
			continue
		}
		if route.source != nil && !route.source.Contains(ci.SourceIP) {
			continue
		}
		log.WithField("resolver", route.resolver.String()).Trace("routing query to resolver")
		return route.resolver.Resolve(q, ci)
	}
	return nil, fmt.Errorf("no route for %s", question.String())
}

// Add a new route to the router. New routes are appended to the existing
// ones and are evaluated in the same order they're added. The default
// route (no name, no type) should be added last since subsequently added
// routes won't have any impact. Name is a regular expression that is
// applied to the name in the first question section of the DNS message.
// Source is an IP or network in CIDR format.
func (r *Router) Add(name, class, typ, source string, resolver Resolver) error {
	t, err := stringToType(typ)
	if err != nil {
		return err
	}
	c, err := stringToClass(class)
	if err != nil {
		return err
	}
	re, err := regexp.Compile(name)
	if err != nil {
		return err
	}
	var sNet *net.IPNet
	if source != "" {
		_, sNet, err = net.ParseCIDR(source)
		if err != nil {
			return err
		}
	}
	newRoute := &route{
		typ:      t,
		class:    c,
		name:     re,
		source:   sNet,
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
	return 0, fmt.Errorf("unknown type '%s'", s)
}

// Convert a DNS class string into is numerical form, for example "INET" -> 1.
func stringToClass(s string) (uint16, error) {
	switch s {
	case "":
		return 0, nil
	case "IN":
		return 1, nil
	case "CH":
		return 3, nil
	case "HS":
		return 4, nil
	case "NONE":
		return 254, nil
	case "ANY":
		return 255, nil
	default:
		return 0, fmt.Errorf("unknown class '%s'", s)
	}
}

type route struct {
	typ      uint16
	class    uint16
	name     *regexp.Regexp
	source   *net.IPNet
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
