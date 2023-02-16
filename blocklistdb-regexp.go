package rdns

import (
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// RegexpDB holds a list of regular expressions against which it evaluates DNS queries.
type RegexpDB struct {
	name   string
	rules  []*regexp.Regexp
	loader BlocklistLoader
}

var _ BlocklistDB = &RegexpDB{}

// NewRegexpDB returns a new instance of a matcher for a list of regular expressions.
func NewRegexpDB(name string, loader BlocklistLoader) *RegexpDB {
	return &RegexpDB{name, nil, loader}
}

func (m *RegexpDB) Reload() (BlocklistDB, error) {
	rules, err := m.loader.Load()
	if err != nil {
		return nil, err
	}
	var filters []*regexp.Regexp

	for _, r := range rules {
		r = strings.TrimSpace(r)
		if r == "" || strings.HasPrefix(r, "#") {
			continue
		}
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, err
		}
		filters = append(filters, re)
	}

	return &RegexpDB{m.name, filters, m.loader}, nil
}

func (m *RegexpDB) Match(q dns.Question) (net.IP, string, *BlocklistMatch, bool) {
	for _, rule := range m.rules {
		if rule.MatchString(q.Name) {
			return nil, "", &BlocklistMatch{List: m.name, Rule: rule.String()}, true
		}
	}
	return nil, "", nil, false
}

func (m *RegexpDB) String() string {
	return "Regexp"
}
