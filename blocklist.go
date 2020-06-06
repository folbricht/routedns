package rdns

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Blocklist is a resolver that returns NXDOMAIN or a spoofed IP for every query that
// matches. Everything else is passed through to another resolver.
type Blocklist struct {
	id string
	BlocklistOptions
	resolver Resolver
	mu       sync.RWMutex
}

var _ Resolver = &Blocklist{}

type BlocklistOptions struct {
	// Optional, send any blocklist match to this resolver rather
	// than return NXDOMAIN.
	BlocklistResolver Resolver

	BlocklistDB BlocklistDB

	// Refresh period for the blocklist. Disabled if 0.
	BlocklistRefresh time.Duration

	// Optional, send anything that matches the allowlist to an
	// alternative resolver rather than the default upstream one.
	AllowListResolver Resolver

	// Rules that override the blocklist rules, effecively negate them.
	AllowlistDB BlocklistDB

	// Refresh period for the allowlist. Disabled if 0.
	AllowlistRefresh time.Duration
}

// NewBlocklist returns a new instance of a blocklist resolver.
func NewBlocklist(id string, resolver Resolver, opt BlocklistOptions) (*Blocklist, error) {
	blocklist := &Blocklist{id: id, resolver: resolver, BlocklistOptions: opt}

	// Start the refresh goroutines if we have a list and a refresh period was given
	if blocklist.BlocklistDB != nil && blocklist.BlocklistRefresh > 0 {
		go blocklist.refreshLoopBlocklist(blocklist.BlocklistRefresh)
	}
	if blocklist.AllowlistDB != nil && blocklist.AllowlistRefresh > 0 {
		go blocklist.refreshLoopAllowlist(blocklist.AllowlistRefresh)
	}
	return blocklist, nil
}

// Resolve a DNS query by first checking the query against the provided matcher.
// Queries that do not match are passed on to the next resolver.
func (r *Blocklist) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	question := q.Question[0]
	log := Log.WithFields(logrus.Fields{"id": r.id, "client": ci.SourceIP, "qname": question.Name})

	r.mu.RLock()
	blocklistDB := r.BlocklistDB
	allowlistDB := r.AllowlistDB
	r.mu.RUnlock()

	// Forward to upstream or the optional allowlist-resolver immediately if there's a match in the allowlist
	if allowlistDB != nil {
		if _, rule, ok := allowlistDB.Match(question); ok {
			log = log.WithField("rule", rule)
			if r.AllowListResolver != nil {
				log.WithField("resolver", r.AllowListResolver.String()).Debug("matched allowlist, forwarding")
				return r.AllowListResolver.Resolve(q, ci)
			}
			log.WithField("resolver", r.resolver.String()).Debug("matched allowlist, forwarding")
			return r.resolver.Resolve(q, ci)
		}
	}

	ip, rule, ok := blocklistDB.Match(question)
	if !ok {
		// Didn't match anything, pass it on to the next resolver
		log.WithField("resolver", r.resolver.String()).Debug("forwarding unmodified query to resolver")
		return r.resolver.Resolve(q, ci)
	}
	log = log.WithField("rule", rule)

	// If an optional blocklist-resolver was given, send the query to that instead of returning NXDOMAIN.
	if r.BlocklistResolver != nil {
		log.WithField("resolver", r.resolver.String()).Debug("matched blocklist, forwarding")
		return r.BlocklistResolver.Resolve(q, ci)
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
	return r.id
}

func (r *Blocklist) refreshLoopBlocklist(refresh time.Duration) {
	for {
		time.Sleep(refresh)
		log := Log.WithField("id", r.id)
		log.Debug("reloading blocklist")
		db, err := r.BlocklistDB.Reload()
		if err != nil {
			log.WithError(err).Error("failed to load rules")
			continue
		}
		r.mu.Lock()
		r.BlocklistDB = db
		r.mu.Unlock()
	}
}
func (r *Blocklist) refreshLoopAllowlist(refresh time.Duration) {
	for {
		time.Sleep(refresh)
		log := Log.WithField("id", r.id)
		log.Debug("reloading allowlist")
		db, err := r.AllowlistDB.Reload()
		if err != nil {
			log.WithError(err).Error("failed to load rules")
			continue
		}
		r.mu.Lock()
		r.AllowlistDB = db
		r.mu.Unlock()
	}
}
