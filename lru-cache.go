package rdns

import (
	"encoding/json"
	"errors"
	"hash/maphash"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// lruCache holds cached DNS responses in a doubly-linked list ordered by
// recency, indexed by a 64-bit hash of the cache key.
//
// Indexing by hash rather than by lruKey directly keeps the 48-byte key out
// of every map slot, which matters because the item already holds the key.
// A lookup compares the full key, so a hash collision can only ever cause a
// cache miss. Two distinct keys colliding on 64 bits is rare enough that the
// loser is dropped rather than chained; the seed is random per instance, so
// a client cannot craft names that collide on purpose.
type lruCache struct {
	maxItems   int
	items      map[uint64]*cacheItem
	head, tail *cacheItem
	seed       maphash.Seed
}

// cacheItem is one entry in the queue, holding the stored form of a response.
type cacheItem struct {
	prev, next *cacheItem
	hash       uint64 // key hash, kept so eviction doesn't have to decode the blob
	blob       cacheBlob
}

type lruKey struct {
	Question dns.Question
	Net      string
	Do       bool
	CD       bool  // RFC 4035 §4.7 / RFC 6840 §5.9: CD=1 responses are unvalidated and must not be served to CD=0 clients
	ECSMask  uint8 // ECS source prefix length; responses with differing scope must not collide
}

type cacheAnswer struct {
	Timestamp        time.Time // Time the record was cached. Needed to adjust TTL
	Expiry           time.Time // Time the record expires and should be removed
	PrefetchEligible bool      // The cache can prefetch this record
	Msg              *dns.Msg
}

// How a cacheItem is written to, and read from, the cache file
// (MemoryBackendOptions.Filename). It mirrors cacheItem/cacheAnswer with the
// message in wire format, which is what makes the record marshalable.
//
// The cache types deliberately don't carry a MarshalJSON method of their own.
// One would have to build its output with json.Marshal, which the encoder then
// re-parses to compact it, encoding every record twice.
type cacheItemJSON struct {
	Key    lruKey
	Answer cacheAnswerJSON
}

type cacheAnswerJSON struct {
	Timestamp        time.Time
	Expiry           time.Time
	PrefetchEligible bool
	Msg              []byte
}

// Builds the on-disk form of an item. The stored blob already holds the
// message in wire format, so the record borrows those bytes rather than
// packing again.
func newCacheItemJSON(item *cacheItem) (cacheItemJSON, error) {
	if len(item.blob) < blobHdrLen {
		return cacheItemJSON{}, errors.New("cache item is malformed")
	}
	return cacheItemJSON{
		Key: item.blob.key(),
		Answer: cacheAnswerJSON{
			Timestamp:        nanoTime(item.blob.timestamp()),
			Expiry:           nanoTime(item.blob.expiry()),
			PrefetchEligible: item.blob.prefetchEligible(),
			Msg:              item.blob.message(),
		},
	}, nil
}

// Conversions between the time.Time a cacheAnswer carries and the unix
// nanoseconds an item holds. The zero time maps to zero, which UnixNano
// cannot represent, and back again; times are written out in UTC so a cache
// file doesn't depend on the timezone of the host that wrote it.
func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func nanoTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// Rebuilds a stored item from its on-disk form. Returns false for a record
// that can't be used, which includes ones written by a version that stored
// different fields.
//
// The file already holds the message in wire format, so it goes into the blob
// as-is. It is still unpacked once here to reject a corrupt record at load
// time rather than on every lookup that finds it.
func (r cacheItemJSON) toCacheItem() (lruKey, cacheBlob, bool) {
	if r.Key.Question.Name == "" || len(r.Answer.Msg) == 0 {
		return lruKey{}, nil, false
	}
	if err := new(dns.Msg).Unpack(r.Answer.Msg); err != nil {
		return lruKey{}, nil, false
	}
	blob, err := newCacheBlobFromWire(r.Key, unixNano(r.Answer.Timestamp), unixNano(r.Answer.Expiry),
		r.Answer.PrefetchEligible, r.Answer.Msg)
	if err != nil {
		return lruKey{}, nil, false
	}
	return r.Key, blob, true
}

func newLRUCache(capacity int) *lruCache {
	head := new(cacheItem)
	tail := new(cacheItem)
	head.next = tail
	tail.prev = head

	return &lruCache{
		maxItems: capacity,
		items:    make(map[uint64]*cacheItem),
		head:     head,
		tail:     tail,
		seed:     maphash.MakeSeed(),
	}
}

// add packs an answer and stores it under the query's key. Packing is done by
// the caller's goroutine before the cache is locked; see memoryBackend.Store.
func (c *lruCache) add(query *dns.Msg, answer *cacheAnswer) error {
	key := lruKeyFromQuery(query)
	blob, err := newCacheBlob(key, answer)
	if err != nil {
		return err
	}
	c.addKey(key, blob)
	return nil
}

func (c *lruCache) addKey(key lruKey, blob cacheBlob) {
	item := c.touch(key)
	if item != nil {
		// Already at the top of the list, so only the blob changes. The old
		// one is left for the collector; a reader may still be decoding it.
		item.blob = blob
		return
	}
	c.insert(&cacheItem{hash: c.hash(key), blob: blob})
}

// Link a new item into the index and the top of the linked list.
func (c *lruCache) insert(item *cacheItem) {
	if existing := c.items[item.hash]; existing != nil {
		c.unlink(existing)
	}
	c.items[item.hash] = item

	item.next = c.head.next
	item.prev = c.head
	c.head.next.prev = item
	c.head.next = item

	c.resize()
}

// Unlink an item from both the index and the linked list.
func (c *lruCache) unlink(item *cacheItem) {
	item.prev.next = item.next
	item.next.prev = item.prev
	delete(c.items, item.hash)
}

func (c *lruCache) hash(key lruKey) uint64 {
	return maphash.Comparable(c.seed, key)
}

// Find an item by key without changing its position in the queue.
func (c *lruCache) find(key lruKey) *cacheItem {
	item := c.items[c.hash(key)]
	if item == nil || !item.blob.matchesKey(key) {
		return nil
	}
	return item
}

// Loads a cache item and puts it to the top of the queue (most recent).
func (c *lruCache) touch(key lruKey) *cacheItem {
	item := c.find(key)
	if item == nil {
		return nil
	}
	// move the item to the top of the linked list
	item.prev.next = item.next
	item.next.prev = item.prev
	item.next = c.head.next
	item.prev = c.head
	c.head.next.prev = item
	c.head.next = item
	return item
}

func (c *lruCache) delete(q *dns.Msg) {
	item := c.find(lruKeyFromQuery(q))
	if item == nil {
		return
	}
	c.unlink(item)
}

func (c *lruCache) get(query *dns.Msg) *cacheItem {
	return c.touch(lruKeyFromQuery(query))
}

// Shrink the cache down to the maximum number of items.
func (c *lruCache) resize() {
	if c.maxItems <= 0 { // no size limit
		return
	}
	for len(c.items) > c.maxItems {
		c.unlink(c.tail.prev)
	}
}

// Clear the cache.
func (c *lruCache) reset() {
	head := new(cacheItem)
	tail := new(cacheItem)
	head.next = tail
	tail.prev = head

	c.head = head
	c.tail = tail
	c.items = make(map[uint64]*cacheItem)
}

// Iterate over the cached items and call the provided function. If it
// returns true, the item is deleted from the cache.
func (c *lruCache) deleteFunc(f func(*cacheItem) bool) {
	item := c.head.next
	for item != c.tail {
		next := item.next
		if f(item) {
			c.unlink(item)
		}
		item = next
	}
}

func (c *lruCache) size() int {
	return len(c.items)
}

func (c *lruCache) serialize(w io.Writer) error {
	enc := json.NewEncoder(w)
	for item := c.tail.prev; item != c.head; item = item.prev {
		record, err := newCacheItemJSON(item)
		if err != nil {
			return err
		}
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func (c *lruCache) deserialize(r io.Reader) error {
	dec := json.NewDecoder(r)
	for dec.More() {
		var record cacheItemJSON
		if err := dec.Decode(&record); err != nil {
			return err
		}
		// Skip bad (or incompatible) records
		key, blob, ok := record.toCacheItem()
		if !ok {
			continue
		}
		c.addKey(key, blob)
	}
	return nil
}

func lruKeyFromQuery(q *dns.Msg) lruKey {
	question := q.Question[0]
	// disregard case of the question name when storing
	question.Name = strings.ToLower(question.Name)
	key := lruKey{Question: question, CD: q.CheckingDisabled}

	edns0 := q.IsEdns0()
	if edns0 != nil {
		key.Do = edns0.Do()
		// See if we have a subnet option
		for _, opt := range edns0.Option {
			if subnet, ok := opt.(*dns.EDNS0_SUBNET); ok {
				key.Net = subnet.Address.String()
				key.ECSMask = subnet.SourceNetmask
			}
		}
	}
	return key
}
