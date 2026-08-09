package rdns

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type lruCache struct {
	maxItems   int
	items      map[lruKey]*cacheItem
	head, tail *cacheItem
}

type cacheItem struct {
	Key        lruKey
	Answer     *cacheAnswer
	prev, next *cacheItem
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

// Builds the on-disk form of an item, packing its message to wire format.
func newCacheItemJSON(item *cacheItem) (cacheItemJSON, error) {
	if item.Answer == nil || item.Answer.Msg == nil {
		return cacheItemJSON{}, errors.New("cache item has no message")
	}
	msg, err := item.Answer.Msg.Pack()
	if err != nil {
		return cacheItemJSON{}, err
	}
	return cacheItemJSON{
		Key: item.Key,
		Answer: cacheAnswerJSON{
			Timestamp:        item.Answer.Timestamp,
			Expiry:           item.Answer.Expiry,
			PrefetchEligible: item.Answer.PrefetchEligible,
			Msg:              msg,
		},
	}, nil
}

// Rebuilds a cache item from its on-disk form, unpacking the wire-format
// message. Returns false for a record that can't be used, which includes ones
// written by a version that stored different fields.
func (r cacheItemJSON) toCacheItem() (lruKey, *cacheAnswer, bool) {
	if r.Key.Question.Name == "" || len(r.Answer.Msg) == 0 {
		return lruKey{}, nil, false
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(r.Answer.Msg); err != nil {
		return lruKey{}, nil, false
	}
	return r.Key, &cacheAnswer{
		Timestamp:        r.Answer.Timestamp,
		Expiry:           r.Answer.Expiry,
		PrefetchEligible: r.Answer.PrefetchEligible,
		Msg:              msg,
	}, true
}

func newLRUCache(capacity int) *lruCache {
	head := new(cacheItem)
	tail := new(cacheItem)
	head.next = tail
	tail.prev = head

	return &lruCache{
		maxItems: capacity,
		items:    make(map[lruKey]*cacheItem),
		head:     head,
		tail:     tail,
	}
}

func (c *lruCache) add(query *dns.Msg, answer *cacheAnswer) {
	key := lruKeyFromQuery(query)
	c.addKey(key, answer)
}

func (c *lruCache) addKey(key lruKey, answer *cacheAnswer) {
	item := c.touch(key)
	if item != nil {
		// Update the item, it's already at the top of the list
		// so we can just change the value
		item.Answer = answer
		return
	}
	// Add new item to the top of the linked list
	item = &cacheItem{
		Key:    key,
		Answer: answer,
		next:   c.head.next,
		prev:   c.head,
	}
	c.head.next.prev = item
	c.head.next = item
	c.items[key] = item
	c.resize()
}

// Loads a cache item and puts it to the top of the queue (most recent).
func (c *lruCache) touch(key lruKey) *cacheItem {
	item := c.items[key]
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
	key := lruKeyFromQuery(q)
	item := c.items[key]
	if item == nil {
		return
	}
	item.prev.next = item.next
	item.next.prev = item.prev
	delete(c.items, key)
}

func (c *lruCache) get(query *dns.Msg) *cacheAnswer {
	key := lruKeyFromQuery(query)
	item := c.touch(key)
	if item != nil {
		return item.Answer
	}
	return nil
}

// Shrink the cache down to the maximum number of items.
func (c *lruCache) resize() {
	if c.maxItems <= 0 { // no size limit
		return
	}
	drop := len(c.items) - c.maxItems
	for range drop {
		item := c.tail.prev
		item.prev.next = c.tail
		c.tail.prev = item.prev
		delete(c.items, item.Key)
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
	c.items = make(map[lruKey]*cacheItem)
}

// Iterate over the cached answers and call the provided function. If it
// returns true, the item is deleted from the cache.
func (c *lruCache) deleteFunc(f func(*cacheAnswer) bool) {
	item := c.head.next
	for item != c.tail {
		if f(item.Answer) {
			item.prev.next = item.next
			item.next.prev = item.prev
			delete(c.items, item.Key)
		}
		item = item.next
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
		key, answer, ok := record.toCacheItem()
		if !ok {
			continue
		}
		c.addKey(key, answer)
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
