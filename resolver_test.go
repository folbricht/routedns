package rdns

import (
	"errors"

	"github.com/miekg/dns"
)

type TestResolver func(*dns.Msg) (*dns.Msg, error)

func (r TestResolver) Resolve(q *dns.Msg) (*dns.Msg, error) {
	if r == nil {
		return nil, errors.New("no function defined in TestResolver")
	}
	return r(q)
}

func (r TestResolver) String() string {
	return "TestResolver()"
}
