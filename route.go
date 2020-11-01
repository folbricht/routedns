package rdns

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

type route struct {
	types    []uint16
	class    uint16
	name     *regexp.Regexp
	source   *net.IPNet
	inverted bool // invert the matching behavior
	resolver Resolver
}

// NewRoute initializes a route from string parameters.
func NewRoute(name, class string, types []string, source string, resolver Resolver) (*route, error) {
	if resolver == nil {
		return nil, errors.New("no resolver defined for route")
	}
	t, err := stringToType(types)
	if err != nil {
		return nil, err
	}
	c, err := stringToClass(class)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(name)
	if err != nil {
		return nil, err
	}
	var sNet *net.IPNet
	if source != "" {
		_, sNet, err = net.ParseCIDR(source)
		if err != nil {
			return nil, err
		}
	}
	return &route{
		types:    t,
		class:    c,
		name:     re,
		source:   sNet,
		resolver: resolver,
	}, nil
}

func (r *route) match(q *dns.Msg, ci ClientInfo) bool {
	question := q.Question[0]
	if !r.matchType(question.Qtype) {
		return r.inverted
	}
	if r.class != 0 && r.class != question.Qclass {
		return r.inverted
	}
	if !r.name.MatchString(question.Name) {
		return r.inverted
	}
	if r.source != nil && !r.source.Contains(ci.SourceIP) {
		return r.inverted
	}
	return !r.inverted
}

func (r *route) Invert(value bool) {
	r.inverted = value
}

func (r *route) String() string {
	if r.isDefault() {
		return fmt.Sprintf("default->%s", r.resolver)
	}
	return fmt.Sprintf("%s->%s", r.name, r.resolver)
}

func (r *route) isDefault() bool {
	return r.class == 0 && len(r.types) == 0 && r.name.String() == ""
}

func (r *route) matchType(typ uint16) bool {
	if len(r.types) == 0 {
		return true
	}
	for _, t := range r.types {
		if t == typ {
			return true
		}
	}
	return false
}

// Convert DNS type strings into the numerical type, for example "A" -> 1.
func stringToType(s []string) ([]uint16, error) {
	if len(s) == 0 {
		return nil, nil
	}
	var types []uint16
loop:
	for _, typ := range s {
		for k, v := range dns.TypeToString {
			if v == strings.ToUpper(typ) {
				types = append(types, k)
				continue loop
			}
		}
		return nil, fmt.Errorf("unknown type '%s'", s)
	}
	return types, nil
}

// Convert a DNS class string into is numerical form, for example "INET" -> 1.
func stringToClass(s string) (uint16, error) {
	switch strings.ToUpper(s) {
	case "":
		return 0, nil
	case "IN", "INET":
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
