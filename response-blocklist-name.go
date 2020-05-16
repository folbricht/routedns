package rdns

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ResponseBlocklistName is a resolver that filters by matching the strings in CNAME, MX,
// NS, PTR and SRV response resocords against a blocklist.
type ResponseBlocklistName struct {
	ResponseBlocklistNameOptions
	resolver Resolver
	mu       sync.RWMutex
}

var _ Resolver = &ResponseBlocklistName{}

type ResponseBlocklistNameOptions struct {
	BlocklistDB BlocklistDB

	// Refresh period for the blocklist. Disabled if 0.
	BlocklistRefresh time.Duration

	// If true, removes matching records from the response rather than replying with NXDOMAIN.
	Filter bool
}

// NewResponseBlocklistName returns a new instance of a response blocklist resolver.
func NewResponseBlocklistName(resolver Resolver, opt ResponseBlocklistNameOptions) (*ResponseBlocklistName, error) {
	blocklist := &ResponseBlocklistName{resolver: resolver, ResponseBlocklistNameOptions: opt}

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
	if err != nil {
		return answer, err
	}
	if r.Filter {
		return r.filterMatch(q, answer)
	}
	return r.blockIfMatch(q, answer)
}

func (r *ResponseBlocklistName) String() string {
	r.mu.RLock()
	blocklistDB := r.BlocklistDB
	r.mu.RUnlock()
	return fmt.Sprintf("ResponseBlocklistName(%s)", blocklistDB)
}

func (r *ResponseBlocklistName) refreshLoopBlocklist(refresh time.Duration) {
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

func (r *ResponseBlocklistName) blockIfMatch(query, answer *dns.Msg) (*dns.Msg, error) {
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
			if _, rule, ok := r.BlocklistDB.Match(dns.Question{Name: name}); ok {
				Log.WithField("rule", rule).Debug("blocking response")
				answer := new(dns.Msg)
				answer.SetReply(query)
				answer.SetRcode(query, dns.RcodeNameError)
				return answer, nil
			}
		}
	}
	return answer, nil
}

func (r *ResponseBlocklistName) filterMatch(query, answer *dns.Msg) (*dns.Msg, error) {
	answer.Answer = r.filterRR(answer.Answer)
	answer.Ns = r.filterRR(answer.Ns)
	answer.Extra = r.filterRR(answer.Extra)
	return answer, nil
}

func (r *ResponseBlocklistName) filterRR(rrs []dns.RR) []dns.RR {
	newRRs := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
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
			newRRs = append(newRRs, rr)
			continue
		}
		if _, rule, ok := r.BlocklistDB.Match(dns.Question{Name: name}); ok {
			Log.WithField("rule", rule).Debug("filtering response")
			continue
		}
		newRRs = append(newRRs, rr)
	}
	return newRRs
}
