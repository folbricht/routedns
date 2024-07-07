package rdns

import (
	"strings"
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

	// Inverted behavior, only allow responses that can be found on at least one list.
	Inverted bool

	// Optional, allows specifying extended errors to be used in the
	// response when blocking.
	EDNS0EDETemplate *EDNS0EDETemplate
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
		log := Log.With("id", r.id)
		log.Debug("reloading blocklist")
		db, err := r.BlocklistDB.Reload()
		if err != nil {
			log.Error("failed to load rules", "error", err)
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
			case *dns.HTTPS:
				name = svcbString(&r.SVCB)
			case *dns.TXT:
				name = strings.Join(r.Txt, " ")
			case *dns.SVCB:
				name = svcbString(r)
			case *dns.SOA:
				name = r.Ns
			default:
				continue
			}
			msg := new(dns.Msg)
			msg.SetQuestion(name, 0)
			if _, _, rule, ok := r.BlocklistDB.Match(msg); ok != r.Inverted {
				log := logger(r.id, query, ci).With("rule", rule.GetRule())
				if r.BlocklistResolver != nil {
					log.With("resolver", r.BlocklistResolver).Debug("blocklist match, forwarding to blocklist-resolver")
					return r.BlocklistResolver.Resolve(query, ci)
				}
				log.Debug("blocking response")
				answer = nxdomain(query)
				if err := r.EDNS0EDETemplate.Apply(answer, EDNS0EDEInput{query, rule}); err != nil {
					log.Error("failed to apply edns0ede template", "error", err)
				}
				return answer, nil
			}
		}
	}
	return answer, nil
}

// Format an SVCB (and HTTPS) record as string like so "TARGET key1=value1 key2=value2"
// For example: ". alpn=h2,h3"
func svcbString(rr *dns.SVCB) string {
	var s strings.Builder
	s.WriteString(rr.Target)
	for _, v := range rr.Value {
		s.WriteString(" ")
		s.WriteString(v.Key().String())
		s.WriteString("=")
		s.WriteString(v.String())
	}
	return s.String()
}
