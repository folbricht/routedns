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
func NewRegexpDB(name string, loader BlocklistLoader) (*RegexpDB, error) {
	var filters []*regexp.Regexp
	err := loadRules(loader, func(r string) error {
		r = strings.TrimSpace(r)
		if r == "" || strings.HasPrefix(r, "#") {
			return nil
		}
		re, err := regexp.Compile(r)
		if err != nil {
			return err
		}
		filters = append(filters, re)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &RegexpDB{name, filters, loader}, nil
}

func (m *RegexpDB) Reload() (BlocklistDB, error) {
	return NewRegexpDB(m.name, m.loader)
}

func (m *RegexpDB) Match(msg *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	q := msg.Question[0]
	name := strings.ToLower(q.Name)
	for _, rule := range m.rules {
		if rule.MatchString(name) {
			return nil, nil, &BlocklistMatch{List: m.name, Rule: rule.String()}, true
		}
	}
	return nil, nil, nil, false
}

func (m *RegexpDB) String() string {
	return "Regexp"
}
