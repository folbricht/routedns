package rdns

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/miekg/dns"
)

// Blocklist is a resolver that returns NXDOMAIN for every query that
// matches its list of regexes. Everything else is passed through to
// another resolver.
type Blocklist struct {
	resolver Resolver
	filters  []*regexp.Regexp
}

// // BlocklistOptions contain blocklist-specific options.
// type BlocklistOptions struct {
// 	Blocklist []string
// }

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
	for _, filter := range r.filters {
		if filter.MatchString(name) {
			Log.Printf("blocking request for '%s' from %s", name, ci.SourceIP)
			a := new(dns.Msg)
			a.SetRcode(q, dns.RcodeNameError)
			return a, nil
		}
	}

	// None of the filters matched, pass it on to the next resolver
	return r.resolver.Resolve(q, ci)
}

func (r *Blocklist) String() string {
	return fmt.Sprintf("Blocklist(items=%d)", len(r.filters))
}
