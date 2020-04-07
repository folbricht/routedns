package rdns

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Blocklist is a resolver that returns NXDOMAIN or a spoofed IP for every query that
// matches. Everything else is passed through to another resolver.
type Blocklist struct {
	resolver Resolver
	db       BlocklistDB
}

var _ Resolver = &Blocklist{}

// NewBlocklist returns a new instance of a blocklist resolver.
func NewBlocklist(resolver Resolver, db BlocklistDB) (*Blocklist, error) {
	return &Blocklist{resolver: resolver, db: db}, nil
}

// Resolve a DNS query by first checking the query against the provided matcher.
// Queries that do not match are passed on to the next resolver.
func (r *Blocklist) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	question := q.Question[0]
	log := Log.WithFields(logrus.Fields{"client": ci.SourceIP, "qname": question.Name})
	ip, ok := r.db.Match(question)
	if !ok {
		// Didn't match anything, pass it on to the next resolver
		log.WithField("resolver", r.resolver.String()).Trace("forwarding unmodified query to resolver")
		return r.resolver.Resolve(q, ci)
	}

	answer := new(dns.Msg)
	answer.SetReply(q)

	// We have an IP address to return, make sure it's of the right type. If not return NXDOMAIN.
	if ip4 := ip.To4(); len(ip4) == net.IPv4len && question.Qtype == dns.TypeA {
		answer.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  question.Qclass,
					Ttl:    3600,
				},
				A: ip,
			},
		}
		log.Debug("spoofing response")
		return answer, nil
	} else if len(ip) == net.IPv6len && question.Qtype == dns.TypeAAAA {
		answer.Answer = []dns.RR{
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  question.Qclass,
					Ttl:    3600,
				},
				AAAA: ip,
			},
		}
		log.Debug("spoofing response")
		return answer, nil
	}

	// Block the request with NXDOMAIN if there was a match but no valid spoofed IP is given
	log.Debug("blocking request")
	answer.SetRcode(q, dns.RcodeNameError)
	return answer, nil
}

func (r *Blocklist) String() string {
	return fmt.Sprintf("Blocklist(%s)", r.db)
}
