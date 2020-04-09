package rdns

import (
	"net"
	"regexp"

	"github.com/miekg/dns"
)

// RegexpDB holds a list of regular expressions against which it evaluates DNS queries.
type RegexpDB struct {
	rules []*regexp.Regexp
}

var _ BlocklistDB = &RegexpDB{}

// NewRegexpDB returns a new instance of a matcher for a list of regular expressions.
func NewRegexpDB(rules ...string) (*RegexpDB, error) {
	var filters []*regexp.Regexp
	for _, r := range rules {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, err
		}
		filters = append(filters, re)
	}

	return &RegexpDB{filters}, nil
}

func (m *RegexpDB) New(rules []string) (BlocklistDB, error) {
	return NewRegexpDB(rules...)
}

func (m *RegexpDB) Match(q dns.Question) (net.IP, string, bool) {
	for _, rule := range m.rules {
		if rule.MatchString(q.Name) {
			return nil, rule.String(), true
		}
	}
	return nil, "", false
}

func (m *RegexpDB) String() string {
	return "Regexp"
}
