package rdns

import (
	"net"
	"regexp"

	"github.com/miekg/dns"
)

// RegexpMatcher holds a list of regular expressions against which it evaluates DNS queries.
type RegexpMatcher struct {
	filters []*regexp.Regexp
}

var _ BlocklistMatcher = &RegexpMatcher{}

// NewRegexpMatcher returns a new instance of a matcher for a list of regular expressions.
func NewRegexpMatcher(items ...string) (*RegexpMatcher, error) {
	var filters []*regexp.Regexp
	for _, s := range items {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		filters = append(filters, re)
	}

	return &RegexpMatcher{filters}, nil
}

func (m *RegexpMatcher) Match(q dns.Question) (net.IP, bool) {
	for _, filter := range m.filters {
		if filter.MatchString(q.Name) {
			return nil, true
		}
	}
	return nil, false
}

func (m *RegexpMatcher) String() string {
	return "Regexp"
}
