package rdns

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	expirationcache "github.com/0xERR0R/expiration-cache"
	"github.com/miekg/dns"
)

// Prefetch monitors queries and initiates queries for any that are requested
// frequently by the client. Requires a cache behind it to be meaningful.
type Prefetch struct {
	id         string
	resolver   Resolver
	options    PrefetchOptions
	nameCache  *expirationcache.ExpirationLRUCache[atomic.Uint64]
	queryCache *expirationcache.ExpirationLRUCache[dns.Msg]
}

var _ Resolver = &Prefetch{}

type PrefetchOptions struct {
	PrefetchWindow    time.Duration
	PrefetchThreshold uint64
	PrefetchCacheSize int
	PrefetchMaxItems  int
}

func NewPrefetch(id string, resolver Resolver, opt PrefetchOptions) *Prefetch {
	return newPrefetchWithShards(id, resolver, opt, 0)
}

// newPrefetchWithShards builds a Prefetch, allowing the cache shard count to be
// overridden. A shards value of 0 selects the default (GOMAXPROCS-based) sizing
// via expirationCacheShards; a non-zero value forces that count, which is used
// by benchmarks to compare sharded against unsharded caches.
func newPrefetchWithShards(id string, resolver Resolver, opt PrefetchOptions, shards uint) *Prefetch {
	if opt.PrefetchWindow == 0 {
		opt.PrefetchWindow = time.Hour
	}
	if opt.PrefetchThreshold == 0 {
		opt.PrefetchThreshold = 5
	}
	if opt.PrefetchCacheSize == 0 {
		opt.PrefetchCacheSize = opt.PrefetchMaxItems * 3
	}

	nameShards := shards
	queryShards := shards
	if shards == 0 {
		nameShards = expirationCacheShards(opt.PrefetchCacheSize)
		queryShards = expirationCacheShards(opt.PrefetchMaxItems)
	}

	r := &Prefetch{
		id:       id,
		resolver: resolver,
		options:  opt,
	}
	r.nameCache = expirationcache.NewCache[atomic.Uint64](context.Background(), expirationcache.Options{
		MaxSize: uint(opt.PrefetchCacheSize),
		Shards:  nameShards,
	})
	r.queryCache = expirationcache.NewCacheWithOnExpired(context.Background(), expirationcache.Options{
		MaxSize: uint(opt.PrefetchMaxItems),
		Shards:  queryShards,
	},
		func(ctx context.Context, key string) (val *dns.Msg, ttl time.Duration) {
			// Check if the query is still eligible for prefetch by looking it up in the nameCache
			v, _ := r.nameCache.Get(key)
			if v == nil || v.Load() < r.options.PrefetchThreshold {
				// No longer eligible for prefetch
				return
			}

			// Grab the query from the query cache
			q, _ := r.queryCache.Get(key)
			if q == nil {
				return
			}
			ci := ClientInfo{Listener: "prefetch"}
			logger(r.id, q, ci).Debug("prefetching")

			// Send the query again, the response should be cached by the resolver.
			// A nil response with no error means the query was dropped.
			answer, err := r.resolver.Resolve(q, ci)
			if err != nil || answer == nil {
				return
			}

			// Check the response can be used for prefetch
			if (answer.Rcode != dns.RcodeSuccess) || answer.Truncated {
				return
			}
			min, ok := minTTL(answer)
			if !ok || min < 2 {
				return
			}

			newTTL := time.Duration(time.Duration(min) * time.Second)
			return q, newTTL
		},
	)

	return r
}

func expirationCacheShards(maxSize int) uint {
	gomaxprocs := runtime.GOMAXPROCS(0)
	if gomaxprocs <= 1 || maxSize == 1 {
		return 0
	}
	return uint(gomaxprocs)
}

func (r *Prefetch) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil { // a nil response with no error means the query was dropped
		return answer, err
	}

	// Check the response can be used for prefetch, return if not
	if (answer.Rcode != dns.RcodeSuccess) || answer.Truncated {
		return answer, nil
	}
	min, ok := minTTL(answer)
	if !ok || min < 2 {
		return answer, nil
	}

	// Generate a key for both caches
	key := fmt.Sprintf("%+v", lruKeyFromQuery(q))

	// Update the hit-counter for this query
	var v *atomic.Uint64
	if v, _ = r.nameCache.Get(key); v == nil {
		v = new(atomic.Uint64)
	}
	v.Add(1)
	r.nameCache.Put(key, v, r.options.PrefetchWindow)

	// Add to the query cache if we reached the threshold
	if count := v.Load(); count >= r.options.PrefetchThreshold {
		prefetchQ := q.Copy()
		ttl := time.Duration(time.Duration(min) * time.Second)
		r.queryCache.Put(key, prefetchQ, ttl)
	}
	return answer, err
}

func (r *Prefetch) String() string {
	return r.id
}
