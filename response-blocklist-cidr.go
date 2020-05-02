package rdns

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ResponseBlocklistCIDR is a resolver that filters by matching the IPs in the response against
// a blocklist.
type ResponseBlocklistCIDR struct {
	ResponseBlocklistCIDROptions
	resolver Resolver
	mu       sync.RWMutex
}

var _ Resolver = &ResponseBlocklistCIDR{}

type ResponseBlocklistCIDROptions struct {
	BlocklistDB IPBlocklistDB

	// Refresh period for the blocklist. Disabled if 0.
	BlocklistRefresh time.Duration
}

// NewResponseBlocklistCIDR returns a new instance of a response blocklist resolver.
func NewResponseBlocklistCIDR(resolver Resolver, opt ResponseBlocklistCIDROptions) (*ResponseBlocklistCIDR, error) {
	blocklist := &ResponseBlocklistCIDR{resolver: resolver, ResponseBlocklistCIDROptions: opt}

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
	for _, rr := range answer.Answer {
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
			Log.WithField("rule", rule).Debug("blocking response")
			answer := new(dns.Msg)
			answer.SetReply(q)
			answer.SetRcode(q, dns.RcodeNameError)
			return answer, nil
		}
	}
	return answer, err
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
