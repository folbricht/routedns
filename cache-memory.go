package rdns

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"log/slog"

	"github.com/miekg/dns"
)

type memoryBackend struct {
	lru *lruCache
	mu  sync.Mutex
	// Serializes cache-file writes against each other. Held for the whole of
	// writeToFile, while mu is only held for the encode itself.
	saveMu sync.Mutex
	opt    MemoryBackendOptions
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

	// Format to write the cache file in, "json" (default) or "raw". Reading
	// detects the format from the file, so this can be changed either way
	// without losing what is already on disk.
	FileFormat string
}

// Values for MemoryBackendOptions.FileFormat.
const (
	CacheFileFormatJSON = "json"
	CacheFileFormatRaw  = "raw"
)

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
		// Clean up temp files left behind by a run that was killed mid-write.
		removeStaleTempFiles(filepath.Dir(opt.Filename))
		b.loadFromFile(opt.Filename)
	}
	go b.startGC(opt.GCPeriod)
	go b.intervalSave()
	return b
}

func (b *memoryBackend) Store(query *dns.Msg, item *cacheAnswer) {
	// Encode before locking. Packing the message is the expensive half of a
	// store and it doesn't need the cache, so queries aren't held up for it.
	key := lruKeyFromQuery(query)
	blob, err := newCacheBlob(key, item)
	if err != nil {
		Log.Warn("failed to encode cache record", "error", err)
		return
	}
	b.mu.Lock()
	b.lru.addKey(key, blob)
	b.mu.Unlock()
}

func (b *memoryBackend) Lookup(q *dns.Msg) (*dns.Msg, bool, bool) {
	// A stored blob is never modified, so only the reference is taken under
	// the lock and everything below runs outside it.
	var blob cacheBlob
	b.mu.Lock()
	if item := b.lru.get(q); item != nil {
		blob = item.blob
	}
	b.mu.Unlock()

	// Return a cache-miss if there's no answer record in the map
	if blob == nil {
		return nil, false, false
	}

	// Check if item has expired from the cache
	now := time.Now().UnixNano()
	if now > blob.expiry() {
		b.Evict(q)
		return nil, false, false
	}

	// Unpacking yields a message owned by this caller, so later elements in
	// the chain can modify it without affecting the cached original.
	answer := new(dns.Msg)
	if err := answer.Unpack(blob.message()); err != nil {
		Log.Warn("failed to decode cache record", "error", err)
		b.Evict(q)
		return nil, false, false
	}
	// Nothing expires an entry here but this backend, so a record that has
	// aged out is dropped on the way past.
	if !ageCachedAnswer(answer, q, cacheAge(now, blob.timestamp())) {
		b.Evict(q)
		return nil, false, false
	}

	return answer, blob.prefetchEligible(), true
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
		now := time.Now().UnixNano()
		var total, removed int
		b.mu.Lock()
		b.lru.deleteFunc(func(item *cacheItem) bool {
			if now > item.blob.expiry() {
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
	// Only one save at a time. An interval save can otherwise overlap with the
	// one from Close(), with both writing the same file concurrently. This is
	// a separate lock from b.mu, which is only held for the encode.
	b.saveMu.Lock()
	defer b.saveMu.Unlock()

	log := Log.With("filename", filename)
	log.Info("writing cache file")

	err := writeFileAtomic(filename, func(w io.Writer) error {
		// Queries block for the encode, so hold b.mu for just that. Note the
		// buffered writer may still flush to disk here, under the lock.
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.opt.FileFormat == CacheFileFormatRaw {
			return b.lru.serializeRaw(w)
		}
		return b.lru.serialize(w)
	})
	if err != nil {
		log.Warn("failed to write cache file", "error", err)
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

	// The format is taken from the file rather than from the configuration,
	// so switching FileFormat picks up an existing cache instead of dropping
	// it on the floor.
	r := bufio.NewReaderSize(f, fileBufSize)
	read := b.lru.deserialize
	if isRawCacheFile(r) {
		read = b.lru.deserializeRaw
	}
	if err := read(r); err != nil {
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
