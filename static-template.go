package rdns

import (
	"github.com/miekg/dns"
)

// StaticTemplateResolver is a resolver that always returns a predefined set of records
// which can be customized with information from the question. It is similar to
// StaticResolver but allows the use of templates with placeholders as input.
type StaticTemplateResolver struct {
	id       string
	answer   []*Template
	ns       []*Template
	extra    []*Template
	rcode    int
	truncate bool
	opt      StaticResolverOptions
}

var _ Resolver = &StaticTemplateResolver{}

// NewStaticTemplateResolver returns a new instance of a StaticTemplateResolver resolver.
func NewStaticTemplateResolver(id string, opt StaticResolverOptions) (*StaticTemplateResolver, error) {
	r := &StaticTemplateResolver{id: id, opt: opt}

	for _, record := range opt.Answer {
		tpl, err := NewTemplate(record)
		if err != nil {
			return nil, err
		}
		r.answer = append(r.answer, tpl)
	}
	for _, record := range opt.NS {
		tpl, err := NewTemplate(record)
		if err != nil {
			return nil, err
		}
		r.ns = append(r.ns, tpl)
	}
	for _, record := range opt.Extra {
		tpl, err := NewTemplate(record)
		if err != nil {
			return nil, err
		}
		r.extra = append(r.extra, tpl)
	}
	r.rcode = opt.RCode
	r.truncate = opt.Truncate

	return r, nil
}

// Resolve a DNS query by incorporating data from the query into a fixed response.
func (r *StaticTemplateResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer := new(dns.Msg)
	answer.SetReply(q)
	answer.RecursionAvailable = q.RecursionDesired
	log := logger(r.id, q, ci)

	answer.Answer = r.processRRTemplates(q, ci, r.answer...)
	answer.Ns = r.processRRTemplates(q, ci, r.ns...)
	answer.Extra = r.processRRTemplates(q, ci, r.extra...)
	answer.Rcode = r.rcode
	answer.Truncated = r.truncate

	if err := r.opt.EDNS0EDETemplate.Apply(answer, EDNS0EDEInput{q, nil}); err != nil {
		log.WithError(err).Error("failed to apply edns0ede template")
	}

	logger(r.id, q, ci).WithField("truncated", r.truncate).Debug("responding")

	return answer, nil
}

func (r *StaticTemplateResolver) String() string {
	return r.id
}

func (r *StaticTemplateResolver) processRRTemplates(q *dns.Msg, ci ClientInfo, templates ...*Template) []dns.RR {
	log := logger(r.id, q, ci)

	resp := make([]dns.RR, 0, len(templates))
	var question dns.Question
	if len(q.Question) > 0 {
		question = q.Question[0]
	}
	input := templateInput{
		ID:            q.Id,
		Question:      question.Name,
		QuestionClass: dns.ClassToString[question.Qclass],
		QuestionType:  dns.TypeToString[question.Qtype],
	}
	for _, tpl := range templates {
		text, err := tpl.Apply(input)
		if err != nil {
			log.WithError(err).Error("failed to apply template")
			continue
		}

		rr, err := dns.NewRR(text)
		if err != nil {
			log.WithError(err).Error("failed to parse template output")
			continue
		}
		// Update the name of every answer record to match that of the query
		// rr.Header().Name = qName(q)
		resp = append(resp, rr)
	}
	return resp
}
