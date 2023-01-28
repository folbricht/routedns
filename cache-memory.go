package rdns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type memoryBackend struct {
	lru     *lruCache
	mu      sync.Mutex
	metrics *CacheMetrics
}

var _ cacheBackend = (*memoryBackend)(nil)

func newMemoryBackend(capacity int, gcperiod time.Duration, metrics *CacheMetrics) *memoryBackend {
	b := &memoryBackend{
		lru:     newLRUCache(capacity),
		metrics: metrics,
	}
	go b.startGC(gcperiod)
	return b
}

func (b *memoryBackend) Store(query *dns.Msg, item *cacheAnswer) {
	b.mu.Lock()
	b.lru.add(query, item)
	b.mu.Unlock()
}

func (b *memoryBackend) Lookup(q *dns.Msg) (*dns.Msg, bool, bool) {
	var answer *dns.Msg
	var timestamp time.Time
	var prefetchEligible bool
	b.mu.Lock()
	if a := b.lru.get(q); a != nil {
		answer = a.Copy()
		timestamp = a.timestamp
		prefetchEligible = a.prefetchEligible
	}
	b.mu.Unlock()

	// Return a cache-miss if there's no answer record in the map
	if answer == nil {
		return nil, false, false
	}

	// Make a copy of the response before returning it. Some later
	// elements might make changes.
	answer = answer.Copy()
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
				b.Evict(q)
				return nil, false, false
			}
			h.Ttl -= age
		}
	}

	return answer, prefetchEligible, true
}

func (b *memoryBackend) Evict(queries ...*dns.Msg) {
	b.mu.Lock()
	for _, query := range queries {
		b.lru.delete(query)
	}
	b.mu.Unlock()
}

func (b *memoryBackend) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lru.reset()
}

// Runs every period time and evicts all items from the cache that are
// older than max, regardless of TTL. Note that the cache can hold old
// records that are no longer valid. These will only be evicted once
// a new query for them is made (and TTL is too old) or when they are
// older than max.
func (b *memoryBackend) startGC(period time.Duration) {
	for {
		time.Sleep(period)
		now := time.Now()
		var total, removed int
		b.mu.Lock()
		b.lru.deleteFunc(func(a *cacheAnswer) bool {
			if now.After(a.expiry) {
				removed++
				return true
			}
			return false
		})
		total = b.lru.size()
		b.mu.Unlock()

		b.metrics.entries.Set(int64(total))
		Log.WithFields(logrus.Fields{"total": total, "removed": removed}).Trace("cache garbage collection")
	}
}
