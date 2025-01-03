package rdns

import (
	"os"
	"sync"
	"time"

	"log/slog"

	"github.com/miekg/dns"
)

type memoryBackend struct {
	lru *lruCache
	mu  sync.Mutex
	opt MemoryBackendOptions
}

type MemoryBackendOptions struct {
	// Total capacity of the cache, default unlimited
	Capacity int

	// How often to run garbage collection, default 1 minute
	GCPeriod time.Duration

	// Load the cache from file on startup and write it on close
	Filename string

	// Write the file in an interval. Only write on shutdown if not set
	SaveInterval time.Duration
}

var _ CacheBackend = (*memoryBackend)(nil)

func NewMemoryBackend(opt MemoryBackendOptions) *memoryBackend {
	if opt.GCPeriod == 0 {
		opt.GCPeriod = time.Minute
	}
	b := &memoryBackend{
		lru: newLRUCache(opt.Capacity),
		opt: opt,
	}
	if opt.Filename != "" {
		b.loadFromFile(opt.Filename)
	}
	go b.startGC(opt.GCPeriod)
	go b.intervalSave()
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
	var expiry time.Time
	b.mu.Lock()
	if a := b.lru.get(q); a != nil {
		answer = a.Msg.Copy()
		timestamp = a.Timestamp
		prefetchEligible = a.PrefetchEligible
		expiry = a.Expiry
	}
	b.mu.Unlock()

	// Return a cache-miss if there's no answer record in the map
	if answer == nil {
		return nil, false, false
	}

	// Check if item has expired from the cache
	if time.Now().After(expiry) {
		b.Evict(q)
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
			if now.After(a.Expiry) {
				removed++
				return true
			}
			return false
		})
		total = b.lru.size()
		b.mu.Unlock()

		Log.Debug("cache garbage collection",
			slog.Group("details",
				slog.Int("total", total),
				slog.Int("removed", removed),
			),
		)
	}
}

func (b *memoryBackend) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lru.size()
}

func (b *memoryBackend) Close() error {
	if b.opt.Filename != "" {
		return b.writeToFile(b.opt.Filename)
	}
	return nil
}

func (b *memoryBackend) writeToFile(filename string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	log := Log.With("filename", filename)
	log.Info("writing cache file")
	f, err := os.Create(filename)
	if err != nil {
		log.Warn("failed to create cache file", "error", err)
		return err
	}
	defer f.Close()

	if err := b.lru.serialize(f); err != nil {
		log.Warn("failed to persist cache to disk", "error", err)
		return err
	}
	return nil
}

func (b *memoryBackend) loadFromFile(filename string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	log := Log.With("filename", filename)
	log.Info("reading cache file")
	f, err := os.Open(filename)
	if err != nil {
		log.Warn("failed to open cache file", "error", err)
		return err
	}
	defer f.Close()

	if err := b.lru.deserialize(f); err != nil {
		log.Warn("failed to read cache from disk", "error", err)
		return err
	}
	return nil
}

func (b *memoryBackend) intervalSave() {
	if b.opt.Filename == "" || b.opt.SaveInterval == 0 {
		return
	}
	for {
		time.Sleep(b.opt.SaveInterval)
		b.writeToFile(b.opt.Filename)
	}
}
