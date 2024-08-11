package rdns

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// IPBlocklistDB is a database containing IPs used in blocklists.
type IPBlocklistDB interface {
	Reload() (IPBlocklistDB, error)
	Match(ip net.IP) (*BlocklistMatch, bool)
	Close() error
	fmt.Stringer
}

// ResponseBlocklistIP is a resolver that filters by matching the IPs in the response against
// a blocklist.
type ResponseBlocklistIP struct {
	id string
	ResponseBlocklistIPOptions
	resolver Resolver
	mu       sync.RWMutex
}

var _ Resolver = &ResponseBlocklistIP{}

type ResponseBlocklistIPOptions struct {
	// Optional, if the response is found to match the blocklist, send the query to this resolver.
	BlocklistResolver Resolver

	BlocklistDB IPBlocklistDB

	// Refresh period for the blocklist. Disabled if 0.
	BlocklistRefresh time.Duration

	// If true, removes matching records from the response rather than replying with NXDOMAIN. Can
	// not be combined with alternative blocklist-resolver
	Filter bool

	// Inverted behavior, only allow responses that can be found on at least one list.
	Inverted bool

	// Optional, allows specifying extended errors to be used in the
	// response when blocking.
	EDNS0EDETemplate *EDNS0EDETemplate
}

// NewResponseBlocklistIP returns a new instance of a response blocklist resolver.
func NewResponseBlocklistIP(id string, resolver Resolver, opt ResponseBlocklistIPOptions) (*ResponseBlocklistIP, error) {
	blocklist := &ResponseBlocklistIP{id: id, resolver: resolver, ResponseBlocklistIPOptions: opt}

	// Start the refresh goroutines if we have a list and a refresh period was given
	if blocklist.BlocklistDB != nil && blocklist.BlocklistRefresh > 0 {
		go blocklist.refreshLoopBlocklist(blocklist.BlocklistRefresh)
	}
	return blocklist, nil
}

// Resolve a DNS query by first querying the upstream resolver, then checking any IP responses
// against a blocklist. Responds with NXDOMAIN if the response IP is in the filter-list.
func (r *ResponseBlocklistIP) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil {
		return answer, err
	}
	if answer.Rcode != dns.RcodeSuccess {
		return answer, err
	}
	if r.Filter {
		return r.filterMatch(q, answer, ci)
	}
	return r.blockIfMatch(q, answer, ci)
}

func (r *ResponseBlocklistIP) String() string {
	return r.id
}

func (r *ResponseBlocklistIP) refreshLoopBlocklist(refresh time.Duration) {
	for {
		time.Sleep(refresh)
		log := Log.WithField("id", r.id)
		log.Debug("reloading blocklist")
		db, err := r.BlocklistDB.Reload()
		if err != nil {
			Log.WithError(err).Error("failed to load rules")
			continue
		}
		r.mu.Lock()
		r.BlocklistDB.Close()
		r.BlocklistDB = db
		r.mu.Unlock()
	}
}

func (r *ResponseBlocklistIP) blockIfMatch(query, answer *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	for _, records := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, rr := range records {
			var ip net.IP
			switch r := rr.(type) {
			case *dns.A:
				ip = r.A
			case *dns.AAAA:
				ip = r.AAAA
			default:
				continue
			}
			if match, ok := r.BlocklistDB.Match(ip); ok != r.Inverted {
				log := logger(r.id, query, ci).WithFields(logrus.Fields{"list": match.GetList(), "rule": match.GetRule(), "ip": ip})
				if r.BlocklistResolver != nil {
					log.WithField("resolver", r.BlocklistResolver).Debug("blocklist match, forwarding to blocklist-resolver")
					return r.BlocklistResolver.Resolve(query, ci)
				}
				log.Debug("blocking response")
				answer = nxdomain(query)
				if err := r.EDNS0EDETemplate.Apply(answer, EDNS0EDEInput{query, match}); err != nil {
					log.WithError(err).Error("failed to apply edns0ede template")
				}
				return answer, nil
			}
		}
	}
	return answer, nil
}

func (r *ResponseBlocklistIP) filterMatch(query, answer *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer.Answer = r.filterRR(query, ci, answer.Answer)
	// If there's nothing left after applying the filter, return NXDOMAIN or send to the alternative resolver
	if len(answer.Answer) == 0 {
		log := Log.WithFields(logrus.Fields{"qname": qName(query)})
		if r.BlocklistResolver != nil {
			log.WithField("resolver", r.BlocklistResolver).Debug("no answers after filtering, forwarding to blocklist-resolver")
			return r.BlocklistResolver.Resolve(query, ci)
		}
		log.Debug("no answers after filtering, blocking response")
		return nxdomain(query), nil
	}
	answer.Ns = r.filterRR(query, ci, answer.Ns)
	answer.Extra = r.filterRR(query, ci, answer.Extra)
	return answer, nil
}

func (r *ResponseBlocklistIP) filterRR(query *dns.Msg, ci ClientInfo, rrs []dns.RR) []dns.RR {
	newRRs := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		var ip net.IP
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
		case *dns.AAAA:
			ip = r.AAAA
		default:
			newRRs = append(newRRs, rr)
			continue
		}
		if match, ok := r.BlocklistDB.Match(ip); ok != r.Inverted {
			logger(r.id, query, ci).WithFields(logrus.Fields{"list": match.GetList(), "rule": match.GetRule(), "ip": ip}).Debug("filtering response")
			continue
		}
		newRRs = append(newRRs, rr)
	}
	return newRRs
}
