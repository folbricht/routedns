package rdns

import (
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
	rcode    int
	truncate bool
	opt      StaticResolverOptions
}

var _ Resolver = &StaticResolver{}

type StaticResolverOptions struct {
	// Records in zone-file format
	Answer   []string
	NS       []string
	Extra    []string
	RCode    int
	Truncate bool
	// Optional, allows specifying extended errors to be used in the
	// response when blocking.
	EDNS0EDETemplate *EDNS0EDETemplate
}

// NewStaticResolver returns a new instance of a StaticResolver resolver.
func NewStaticResolver(id string, opt StaticResolverOptions) (*StaticResolver, error) {
	r := &StaticResolver{id: id, opt: opt}

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
	r.rcode = opt.RCode
	r.truncate = opt.Truncate

	return r, nil
}

// Resolve a DNS query by returning a fixed response.
func (r *StaticResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer := new(dns.Msg)
	answer.SetReply(q)
	answer.RecursionAvailable = q.RecursionDesired
	log := logger(r.id, q, ci)

	// Update the name of every answer record to match that of the query
	answer.Answer = make([]dns.RR, 0, len(r.answer))
	for _, rr := range r.answer {
		r := dns.Copy(rr)
		r.Header().Name = qName(q)
		answer.Answer = append(answer.Answer, r)
	}
	answer.Ns = r.ns
	answer.Extra = r.extra
	answer.Rcode = r.rcode
	answer.Truncated = r.truncate

	if err := r.opt.EDNS0EDETemplate.Apply(answer, EDNS0EDEInput{q, nil}); err != nil {
		log.Error("failed to apply edns0ede template", "error", err)
	}

	logger(r.id, q, ci).With("truncated", r.truncate).Debug("responding")

	return answer, nil
}

func (r *StaticResolver) String() string {
	return r.id
}
