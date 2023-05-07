package rdns

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
)

// Replace is a resolver that modifies queries according to regular expressions
// and forwards the modified queries to another resolver. Responses are then
// mapped back to the original query string.
type SubDomainReplace struct {
	id       string
	resolver Resolver
	exp      subDomainReplaceExpressions
}

var _ Resolver = &SubDomainReplace{}

type subDomainReplaceExp struct {
	from string
	to   string
}

type subDomainReplaceExpressions []subDomainReplaceExp

func (r subDomainReplaceExp) substitute(qname string) (string, bool) {
	fromDomain := r.from
	toDomain := r.to
	// from {}.ctptech.dev to {}.charlesp.tech
	// from test.ctptech.dev to test.charlesp.tech
	if strings.HasSuffix(qname, fromDomain) {
		str := strings.Replace(qname, fromDomain, toDomain, 1)
		Log.WithField("qname", qname).Debug("matches: modifying query")
		return str, true
	} else {
		return "", false
	}
}
func (r subDomainReplaceExpressions) apply(qname string) string {
	for _, e := range r {
		s, result := e.substitute(qname)
		if result {
			return s
		}
	}
	return qname
}

type SubDomainReplaceOperation struct {
	From string
	To   string
}

// NewReplace returns a new instance of a Replace resolver.
func NewSubDomainReplace(id string, resolver Resolver, list ...SubDomainReplaceOperation) (*SubDomainReplace, error) {
	var exp subDomainReplaceExpressions
	for _, o := range list {
		if strings.Contains(o.From, "{}") && strings.Contains(o.To, "{}") {
			exp = append(exp, subDomainReplaceExp{o.From, o.To})
		} else {
			return nil, errors.New("{} not found")
		}
	}
	Log.WithField("exp", exp).Debug("exp query")
	return &SubDomainReplace{id: id, resolver: resolver, exp: exp}, nil
}

// Resolve a DNS query by first replacing the query string with another
// sending the query upstream and replace the name in the response with
// the original query string again.
func (r *SubDomainReplace) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}

	oldName := q.Question[0].Name
	newName := r.exp.apply(oldName)
	log := logger(r.id, q, ci)

	// if nothing needs modifying, we can stop here and use the original query
	if newName == oldName {
		log.Debug("forwarding unmodified query to resolver")
		return r.resolver.Resolve(q, ci)
	}

	// Modify the query string
	q.Question[0].Name = newName

	// Send the query upstream
	log.WithField("new-qname", newName).WithField("resolver", r.resolver).Debug("forwarding modified query to resolver")
	a, err := r.resolver.Resolve(q, ci)
	if err != nil || a == nil {
		return nil, err
	}

	// Set the question back to the original name
	a.Question[0].Name = oldName

	// Now put the original name in all answer records that have the
	// new name
	for _, answer := range a.Answer {
		if answer.Header().Name == newName {
			answer.Header().Name = oldName
		}
	}
	return a, nil
}

func (r *SubDomainReplace) String() string {
	return r.id
}
