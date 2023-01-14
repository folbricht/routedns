package rdns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ResponseBlocklistName is a resolver that filters by matching the strings in CNAME, MX,
// NS, PTR and SRV response records against a blocklist.
type ResponseBlocklistName struct {
	id string
	ResponseBlocklistNameOptions
	resolver Resolver
	mu       sync.RWMutex
}

var _ Resolver = &ResponseBlocklistName{}

type ResponseBlocklistNameOptions struct {
	// Optional, if the response is found to match the blocklist, send the query to this resolver.
	BlocklistResolver Resolver

	BlocklistDB BlocklistDB

	// Refresh period for the blocklist. Disabled if 0.
	BlocklistRefresh time.Duration
}

// NewResponseBlocklistName returns a new instance of a response blocklist resolver.
func NewResponseBlocklistName(id string, resolver Resolver, opt ResponseBlocklistNameOptions) (*ResponseBlocklistName, error) {
	blocklist := &ResponseBlocklistName{id: id, resolver: resolver, ResponseBlocklistNameOptions: opt}

	// Start the refresh goroutines if we have a list and a refresh period was given
	if blocklist.BlocklistDB != nil && blocklist.BlocklistRefresh > 0 {
		go blocklist.refreshLoopBlocklist(blocklist.BlocklistRefresh)
	}
	return blocklist, nil
}

// Resolve a DNS query by first querying the upstream resolver, then checking any responses with
// strings against a blocklist. Responds with NXDOMAIN if the response matches the filter.
func (r *ResponseBlocklistName) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil {
		return answer, err
	}
	return r.blockIfMatch(q, answer, ci)
}

func (r *ResponseBlocklistName) String() string {
	return r.id
}

func (r *ResponseBlocklistName) refreshLoopBlocklist(refresh time.Duration) {
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
		r.BlocklistDB = db
		r.mu.Unlock()
	}
}

func (r *ResponseBlocklistName) blockIfMatch(query, answer *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	for _, records := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, rr := range records {
			var name string
			switch r := rr.(type) {
			case *dns.CNAME:
				name = r.Target
			case *dns.MX:
				name = r.Mx
			case *dns.NS:
				name = r.Ns
			case *dns.PTR:
				name = r.Ptr
			case *dns.SRV:
				name = r.Target
			default:
				continue
			}
			if _, _, rule, ok := r.BlocklistDB.Match(dns.Question{Name: name}); ok {
				log := logger(r.id, query, ci).WithField("rule", rule.Rule)
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
