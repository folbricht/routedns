package rdns

import (
	"regexp"

	"github.com/miekg/dns"
)

// StaticResolver is a resolver that always returns the same answer, to any question.
// Typically used in combination with a blocklist to define fixed block responses or
// with a router when building a walled garden.
type StaticResolver struct {
	id       string
	answer   []dns.RR
	ns       []dns.RR
	extra    []dns.RR
	question *regexp.Regexp
	opt      StaticResolverOptions
}

var _ Resolver = &StaticResolver{}

type StaticResolverOptions struct {
	// Records in zone-file format
	Answer   []string
	NS       []string
	Extra    []string
	EDNS0EDE *dns.EDNS0_EDE
	RCode    int
	Truncate bool
	Query    string
}

// NewStaticResolver returns a new instance of a StaticResolver resolver.
func NewStaticResolver(id string, opt StaticResolverOptions) (*StaticResolver, error) {
	r := &StaticResolver{id: id, opt: opt}

	if opt.Query != "" {
		qr, err := regexp.Compile(opt.Query)
		if err != nil {
			return nil, err
		}
		r.question = qr
	} else {
		// pre-compile the answers if we don't have a regex to apply
		for _, record := range opt.Answer {
			rr, err := dns.NewRR(record)
			if err != nil {
				return nil, err
			}
			r.answer = append(r.answer, rr)
		}
		for _, record := range opt.NS {
			rr, err := dns.NewRR(record)
			if err != nil {
				return nil, err
			}
			r.ns = append(r.ns, rr)
		}
		for _, record := range opt.Extra {
			rr, err := dns.NewRR(record)
			if err != nil {
				return nil, err
			}
			r.extra = append(r.extra, rr)
		}
	}

	return r, nil
}

// Resolve a DNS query by returning a fixed response.
func (r *StaticResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer := new(dns.Msg)
	answer.SetReply(q)
	answer.Rcode = r.opt.RCode
	answer.Truncated = r.opt.Truncate
	answer.RecursionAvailable = q.RecursionDesired

	// Apply any templates if we have a query regex
	if r.question != nil {
		answer.Answer = make([]dns.RR, 0, len(r.opt.Answer))
		for _, record := range r.opt.Answer {
			record = r.question.ReplaceAllString(qName(q), record)
			rr, err := dns.NewRR(record)
			if err != nil {
				return nil, err
			}
			answer.Answer = append(answer.Answer, rr)
		}

		answer.Ns = make([]dns.RR, 0, len(r.opt.NS))
		for _, record := range r.opt.NS {
			record = r.question.ReplaceAllString(qName(q), record)
			rr, err := dns.NewRR(record)
			if err != nil {
				return nil, err
			}
			answer.Ns = append(answer.Ns, rr)
		}

		answer.Extra = make([]dns.RR, 0, len(r.opt.Extra))
		for _, record := range r.opt.Extra {
			record = r.question.ReplaceAllString(qName(q), record)
			rr, err := dns.NewRR(record)
			if err != nil {
				return nil, err
			}
			answer.Extra = append(answer.Extra, rr)
		}
		if r.opt.EDNS0EDE != nil {
			text := r.question.ReplaceAllString(qName(q), r.opt.EDNS0EDE.ExtraText)
			answer.SetEdns0(4096, false)
			opt := answer.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{
				InfoCode:  r.opt.EDNS0EDE.InfoCode,
				ExtraText: text,
			})
		}
	} else {
		answer.Answer = r.answer
		answer.Ns = r.ns
		answer.Extra = r.extra
		if r.opt.EDNS0EDE != nil {
			answer.SetEdns0(4096, false)
			opt := answer.IsEdns0()
			opt.Option = append(opt.Option, r.opt.EDNS0EDE)
		}
	}

	// Update the name of every answer record to match that of the query
	for i, rr := range answer.Answer {
		r := dns.Copy(rr)
		r.Header().Name = qName(q)
		answer.Answer[i] = r
	}

	logger(r.id, q, ci).WithField("truncated", r.opt.Truncate).Debug("responding")

	return answer, nil
}

func (r *StaticResolver) String() string {
	return r.id
}
