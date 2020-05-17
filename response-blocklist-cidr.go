package rdns

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// IPBlocklistDB is a database containing IPs used in blocklists.
type IPBlocklistDB interface {
	Reload() (IPBlocklistDB, error)
	Match(ip net.IP) (string, bool)
	fmt.Stringer
}

// ResponseBlocklistCIDR is a resolver that filters by matching the IPs in the response against
// a blocklist.
type ResponseBlocklistCIDR struct {
	ResponseBlocklistCIDROptions
	resolver Resolver
	mu       sync.RWMutex
}

var _ Resolver = &ResponseBlocklistCIDR{}

type ResponseBlocklistCIDROptions struct {
	// Optional, if the response is found to match the blocklist, send the query to this resolver.
	BlocklistResolver Resolver

	BlocklistDB IPBlocklistDB

	// Refresh period for the blocklist. Disabled if 0.
	BlocklistRefresh time.Duration

	// If true, removes matching records from the response rather than replying with NXDOMAIN. Can
	// not be combined with alternative blockist-resolver
	Filter bool
}

// NewResponseBlocklistCIDR returns a new instance of a response blocklist resolver.
func NewResponseBlocklistCIDR(resolver Resolver, opt ResponseBlocklistCIDROptions) (*ResponseBlocklistCIDR, error) {
	blocklist := &ResponseBlocklistCIDR{resolver: resolver, ResponseBlocklistCIDROptions: opt}

	if opt.Filter && opt.BlocklistResolver != nil {
		return nil, errors.New("the 'filter' feature can not be used with 'blocklist-resolver'")
	}

	// Start the refresh goroutines if we have a list and a refresh period was given
	if blocklist.BlocklistDB != nil && blocklist.BlocklistRefresh > 0 {
		go blocklist.refreshLoopBlocklist(blocklist.BlocklistRefresh)
	}
	return blocklist, nil
}

// Resolve a DNS query by first querying the upstream resolver, then checking any IP responses
// against a blocklist. Responds with NXDOMAIN if the response IP is in the filter-list.
func (r *ResponseBlocklistCIDR) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil {
		return answer, err
	}
	if r.Filter {
		return r.filterMatch(q, answer)
	}
	return r.blockIfMatch(q, answer, ci)
}

func (r *ResponseBlocklistCIDR) String() string {
	r.mu.RLock()
	blocklistDB := r.BlocklistDB
	r.mu.RUnlock()
	return fmt.Sprintf("ResponseBlocklistCIDR(%s)", blocklistDB)
}

func (r *ResponseBlocklistCIDR) refreshLoopBlocklist(refresh time.Duration) {
	for {
		time.Sleep(refresh)
		Log.Debug("reloading blocklist")
		db, err := r.BlocklistDB.Reload()
		if err != nil {
			Log.WithError(err).Error("failed to load rules")
			continue
		}
		r.mu.Lock()
		r.BlocklistDB = db
		r.mu.Unlock()
	}
}

func (r *ResponseBlocklistCIDR) blockIfMatch(query, answer *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
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
			if rule, ok := r.BlocklistDB.Match(ip); ok {
				log := Log.WithField("rule", rule)
				if r.BlocklistResolver != nil {
					log.WithField("resolver", r.BlocklistResolver).Debug("blocklist match, forwarding to blocklist-resolver")
					return r.BlocklistResolver.Resolve(query, ci)
				}
				log.Debug("blocking response")
				return nxdomain(query), nil
			}
		}
	}
	return answer, nil
}

func (r *ResponseBlocklistCIDR) filterMatch(query, answer *dns.Msg) (*dns.Msg, error) {
	answer.Answer = r.filterRR(answer.Answer)
	// If there's nothing left after applying the filter, return NXDOMAIN
	if len(answer.Answer) == 0 {
		return nxdomain(query), nil
	}
	answer.Ns = r.filterRR(answer.Ns)
	answer.Extra = r.filterRR(answer.Extra)
	return answer, nil
}

func (r *ResponseBlocklistCIDR) filterRR(rrs []dns.RR) []dns.RR {
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
		if rule, ok := r.BlocklistDB.Match(ip); ok {
			Log.WithField("rule", rule).Debug("filtering response")
			continue
		}
		newRRs = append(newRRs, rr)
	}
	return newRRs
}
