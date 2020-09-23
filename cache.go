package rdns

import (
	"errors"
	"expvar"
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Cache stores results received from its upstream resolver for
// up to TTL seconds in memory.
type Cache struct {
	CacheOptions
	id       string
	resolver Resolver
	mu       sync.Mutex
	lru      *lruCache
	metrics  *CacheMetrics
}

type CacheMetrics struct {
	// Cache hit count.
	hit *expvar.Int
	// Cache miss count.
	miss *expvar.Int
	// Current cache entry count.
	entries *expvar.Int
}

var _ Resolver = &Cache{}

type CacheOptions struct {
	// Time period the cache garbage collection runs. Defaults to one minute if set to 0.
	GCPeriod time.Duration

	// Max number of responses to keep in the cache. Defaults to 0 which means no limit. If
	// the limit is reached, the least-recently used entry is removed from the cache.
	Capacity int

	// TTL to use for negative responsed that do not have an SOA record, default 60
	NegativeTTL uint32
}

// NewCache returns a new instance of a Cache resolver.
func NewCache(id string, resolver Resolver, opt CacheOptions) *Cache {
	c := &Cache{
		CacheOptions: opt,
		id:           id,
		resolver:     resolver,
		lru:          newLRUCache(opt.Capacity),
		metrics: &CacheMetrics{
			hit:     getVarInt("cache", id, "hit"),
			miss:    getVarInt("cache", id, "miss"),
			entries: getVarInt("cache", id, "entries"),
		},
	}
	if c.GCPeriod == 0 {
		c.GCPeriod = time.Minute
	}
	if c.NegativeTTL == 0 {
		c.NegativeTTL = 60
	}
	go c.startGC(c.GCPeriod)
	return c
}

// Resolve a DNS query by first checking an internal cache for existing
// results
func (r *Cache) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	// While multiple questions in one DNS message is part of the standard,
	// it's not actually supported by servers. If we do get one of those,
	// just pass it through and bypass caching.
	if len(q.Question) > 1 {
		return r.resolver.Resolve(q, ci)
	}

	log := logger(r.id, q, ci)

	// Returned an answer from the cache if one exists
	a, ok := r.answerFromCache(q)
	if ok {
		log.Debug("cache-hit")
		r.metrics.hit.Add(1)
		return a, nil
	}
	r.metrics.miss.Add(1)

	log.WithField("resolver", r.resolver.String()).Debug("cache-miss, forwarding")

	// Get a response from upstream
	a, err := r.resolver.Resolve(q, ci)
	if err != nil || a == nil {
		return nil, err
	}

	// Put the upstream response into the cache and return it
	r.storeInCache(q, a)
	return a, nil
}

func (r *Cache) String() string {
	return r.id
}

// Returns an answer from the cache with it's TTL updated or false in case of a cache-miss.
func (r *Cache) answerFromCache(q *dns.Msg) (*dns.Msg, bool) {
	var answer *dns.Msg
	var timestamp time.Time
	r.mu.Lock()
	if a := r.lru.get(q); a != nil {
		answer = a.Copy()
		timestamp = a.timestamp
	}
	r.mu.Unlock()

	// Return a cache-miss if there's no answer record in the map
	if answer == nil {
		return nil, false
	}
	answer.Id = q.Id

	// Calculate the time the record spent in the cache. We need to
	// subtract that from the TTL of each answer record.
	age := uint32(time.Since(timestamp).Seconds())

	// Go through all the answers, NS, and Extra and adjust the TTL (subtract the time
	// it's spent in the cache). If the record is too old, evict it from the cache
	// and return a cache-miss. OPT records have a TTL of 0 and are ignored.
	for _, rr := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, a := range rr {
			if _, ok := a.(*dns.OPT); ok {
				continue
			}
			h := a.Header()
			if age >= h.Ttl {
				r.evictFromCache(q)
				return nil, false
			}
			h.Ttl -= age
		}
	}

	return answer, true
}

func (r *Cache) storeInCache(query, answer *dns.Msg) {
	now := time.Now()

	// Prepare an item for the cache, without expiry for now
	item := &cacheAnswer{Msg: answer, timestamp: now}

	// Find the lowest TTL in the response, this determines the expiry for the whole answer in the cache.
	min, ok := minTTL(answer)

	// Calculate expiry for the whole record. Negative answers may not have a SOA to use the TTL from.
	switch answer.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError:
		if ok {
			item.expiry = now.Add(time.Duration(min) * time.Second)
		} else {
			item.expiry = now.Add(time.Duration(r.NegativeTTL) * time.Second)
		}
	default:
		return
	}

	// Store it in the cache
	r.mu.Lock()
	r.lru.add(query, item)
	r.mu.Unlock()
}

func (r *Cache) evictFromCache(queries ...*dns.Msg) {
	r.mu.Lock()
	for _, query := range queries {
		r.lru.delete(query)
	}
	r.mu.Unlock()
}

// Runs every period time and evicts all items from the cache that are
// older than max, regardless of TTL. Note that the cache can hold old
// records that are no longer valid. These will only be evicted once
// a new query for them is made (and TTL is too old) or when they are
// older than max.
func (r *Cache) startGC(period time.Duration) {
	for {
		time.Sleep(period)
		now := time.Now()
		var total, removed int
		r.mu.Lock()
		r.lru.deleteFunc(func(a *cacheAnswer) bool {
			if now.After(a.expiry) {
				removed++
				return true
			}
			return false
		})
		total = r.lru.size()
		r.mu.Unlock()

		r.metrics.entries.Set(int64(total))
		Log.WithFields(logrus.Fields{"total": total, "removed": removed}).Trace("cache garbage collection")
	}
}

// Find the lowest TTL in all resource records (except OPT).
func minTTL(answer *dns.Msg) (uint32, bool) {
	var (
		min   uint32 = math.MaxUint32
		found bool
	)
	for _, rr := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, a := range rr {
			if _, ok := a.(*dns.OPT); ok {
				continue
			}
			h := a.Header()
			if h.Ttl < min {
				min = h.Ttl
				found = true
			}
		}
	}
	return min, found
}
