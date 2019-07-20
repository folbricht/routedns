package rdns

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Blocklist is a resolver that returns NXDOMAIN for every query that
// matches its list of regexes. Everything else is passed through to
// another resolver.
type Blocklist struct {
	resolver Resolver
	filters  []*regexp.Regexp
}

var _ Resolver = &Blocklist{}

// NewBlocklist returns a new instance of a blocklist resolver.
func NewBlocklist(resolver Resolver, list ...string) (*Blocklist, error) {
	var filters []*regexp.Regexp
	for _, s := range list {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		filters = append(filters, re)
	}

	return &Blocklist{resolver: resolver, filters: filters}, nil
}

// Resolve a DNS query by first checking the query against a list of items
// to block and return NXDOMAIN for any such matches. Queries that do not
// match are passed on to the next resolver.
func (r *Blocklist) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	name := q.Question[0].Name
	log := Log.WithFields(logrus.Fields{"client": ci.SourceIP, "qname": name})
	for _, filter := range r.filters {
		if filter.MatchString(name) {
			log.Debug("blocking request")
			a := new(dns.Msg)
			a.SetRcode(q, dns.RcodeNameError)
			return a, nil
		}
	}
	log.WithField("resolver", r.resolver.String()).Trace("forwarding unmodified query to resolver")

	// None of the filters matched, pass it on to the next resolver
	return r.resolver.Resolve(q, ci)
}

func (r *Blocklist) String() string {
	return fmt.Sprintf("Blocklist(items=%d)", len(r.filters))
}
