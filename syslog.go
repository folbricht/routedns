package rdns

import (
	"fmt"
	"strings"

	syslog "github.com/RackSec/srslog"
	"github.com/miekg/dns"
)

// Syslog forwards every query unmodified and logs the content to syslog
type Syslog struct {
	id       string
	writer   *syslog.Writer
	resolver Resolver
	opt      SyslogOptions
}

var _ Resolver = &Syslog{}

type SyslogOptions struct {
	// "udp", "tcp", "unix". Defaults to "udp"
	Network string

	// Remote address, defaults to local syslog server
	Address string

	// Priority value as per https://pkg.go.dev/log/syslog#Priority
	Priority int

	// Syslog tag
	Tag string

	// Log requests and/or responses
	LogRequest  bool
	LogResponse bool

	// Log all response records, including those that do not match the query type
	Verbose bool
}

// NewSyslog returns a new instance of a Syslog generator.
func NewSyslog(id string, resolver Resolver, opt SyslogOptions) *Syslog {
	writer, err := syslog.Dial(opt.Network, opt.Address, syslog.Priority(opt.Priority), opt.Tag)
	if err != nil {
		// Log any error but don't block if this fails
		Log.Error("failed to initialize syslog",
			"error", err)
	}
	return &Syslog{
		id:       id,
		writer:   writer,
		resolver: resolver,
		opt:      opt,
	}
}

// Resolve passes a DNS query through unmodified. Query details are sent via syslog.
func (r *Syslog) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	var msg string
	if r.opt.LogRequest {
		msg = fmt.Sprintf("id=%s qid=%d type=query client=%s qtype=%s qname=%s", r.id, q.Id, ci.SourceIP.String(), qType(q), qName(q))
		if _, err := r.writer.Write([]byte(msg)); err != nil {
			logger(r.id, q, ci).Error("failed to send syslog",
				"error", err)
		}
	}

	a, err := r.resolver.Resolve(q, ci)
	if err == nil && a != nil && r.opt.LogResponse {
		if a.Rcode == dns.RcodeSuccess {
			var answerRRs = a.Answer
			// Only print the records that match the query type if verbose=false
			if !r.opt.Verbose {
				answerRRs = make([]dns.RR, 0, len(a.Answer))
				for _, rr := range a.Answer {
					if rr.Header().Rrtype != q.Question[0].Qtype {
						continue
					}
					answerRRs = append(answerRRs, rr)
				}
			}

			for i, rr := range answerRRs {
				s := strings.ReplaceAll(rr.String(), "\t", " ")
				msg = fmt.Sprintf("id=%s qid=%d type=answer answer-num=%d/%d qtype=%s qname=%s answer=%q", r.id, q.Id, i+1, len(answerRRs), qType(q), qName(q), s)
				if _, err := r.writer.Write([]byte(msg)); err != nil {
					logger(r.id, q, ci).Error("failed to send syslog",
						"error", err)
				}
			}
			// Synthesize a NODATA rcode when the response is NOERROR without any response records
			if len(answerRRs) == 0 {
				msg = fmt.Sprintf("id=%s qid=%d type=answer qtype=%s qname=%s rcode=NODATA", r.id, q.Id, qType(q), qName(q))
				if _, err := r.writer.Write([]byte(msg)); err != nil {
					logger(r.id, q, ci).Error("failed to send syslog",
						"error", err)
				}
			}
		} else {
			msg = fmt.Sprintf("id=%s qid=%d type=answer qtype=%s qname=%s rcode=%s", r.id, q.Id, qType(q), qName(q), dns.RcodeToString[a.Rcode])
			if _, err := r.writer.Write([]byte(msg)); err != nil {
				logger(r.id, q, ci).Error("failed to send syslog",
					"error", err)
			}
		}
	}
	return a, err
}

func (r *Syslog) String() string {
	return r.id
}
