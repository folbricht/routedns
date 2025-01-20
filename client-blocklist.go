package rdns

import (
	"sync"
	"time"

	"log/slog"

	"github.com/miekg/dns"
)

// ClientBlocklist is a resolver that matches the IPs of clients against a blocklist
type ClientBlocklist struct {
	id string
	ClientBlocklistOptions
	resolver Resolver
	mu       sync.RWMutex
	metrics  *BlocklistMetrics
}

var _ Resolver = &ClientBlocklist{}

type ClientBlocklistOptions struct {
	// Optional, if the client is found to match the blocklist, send the query to this resolver.
	BlocklistResolver Resolver

	BlocklistDB IPBlocklistDB

	// Refresh period for the blocklist. Disabled if 0.
	BlocklistRefresh time.Duration

	// Use the provided ECS address instead of the real client IP if one was
	// provided. This can be used to "test" blocklists by simulating different
	// client IPs.
	UseECS bool
}

// NewClientBlocklistIP returns a new instance of a client blocklist resolver.
func NewClientBlocklist(id string, resolver Resolver, opt ClientBlocklistOptions) (*ClientBlocklist, error) {
	blocklist := &ClientBlocklist{
		id:                     id,
		resolver:               resolver,
		ClientBlocklistOptions: opt,
		metrics:                NewBlocklistMetrics(id),
	}

	// Start the refresh goroutines if we have a list and a refresh period was given
	if blocklist.BlocklistDB != nil && blocklist.BlocklistRefresh > 0 {
		go blocklist.refreshLoopBlocklist(blocklist.BlocklistRefresh)
	}
	return blocklist, nil
}

// Resolve a DNS query after checking the client's IP against a blocklist. Responds with
// REFUSED if the client IP is on the blocklist, or sends the query to an alternative
// resolver if one is configured.
func (r *ClientBlocklist) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	ip := ci.SourceIP

	// Use the ECS IP if one is available and useECS is set
	if r.UseECS {
		edns0 := q.IsEdns0()
		if edns0 != nil {
			for _, opt := range edns0.Option {
				if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
					ip = ecs.Address
					break
				}
			}
		}
	}

	if match, ok := r.BlocklistDB.Match(ip); ok {
		log := Log.With(
			slog.String("id", r.id),
			slog.String("qname", qName(q)),
			slog.String("list", match.List),
			slog.String("rule", match.Rule),
			slog.String("ip", ci.SourceIP.String()),
		)
		r.metrics.blocked.Add(1)
		if r.BlocklistResolver != nil {
			log.With(
				slog.String("resolver", r.BlocklistResolver.String()),
			).Debug("client on blocklist, forwarding to blocklist-resolver")
			return r.BlocklistResolver.Resolve(q, ci)
		}
		log.Debug("blocking client")
		return refused(q), nil
	}

	r.metrics.allowed.Add(1)
	return r.resolver.Resolve(q, ci)
}

func (r *ClientBlocklist) String() string {
	return r.id
}

func (r *ClientBlocklist) refreshLoopBlocklist(refresh time.Duration) {
	for {
		time.Sleep(refresh)
		log := Log.With(
			slog.String("id", r.id),
		)
		log.Debug("reloading blocklist")
		db, err := r.BlocklistDB.Reload()
		if err != nil {
			log.Error("failed to load rules",
				"error", err)
			continue
		}
		r.mu.Lock()
		r.BlocklistDB.Close()
		r.BlocklistDB = db
		r.mu.Unlock()
	}
}
