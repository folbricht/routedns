package rdns

import (
	"encoding/json"
	"io"
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
}

type cacheAnswer struct {
	Timestamp        time.Time // Time the record was cached. Needed to adjust TTL
	Expiry           time.Time // Time the record expires and should be removed
	PrefetchEligible bool      // The cache can prefetch this record
	Msg              *dns.Msg
}

func (c cacheAnswer) MarshalJSON() ([]byte, error) {
	msg, err := c.Msg.Pack()
	if err != nil {
		return nil, err
	}
	type alias cacheAnswer
	record := struct {
		alias
		Msg []byte
	}{
		alias: alias(c),
		Msg:   msg,
	}
	return json.Marshal(record)
}

func (c *cacheAnswer) UnmarshalJSON(data []byte) error {
	type alias cacheAnswer
	aux := struct {
		*alias
		Msg []byte
	}{
		alias: (*alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.Msg = new(dns.Msg)
	return c.Msg.Unpack(aux.Msg)
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
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func (c *lruCache) deserialize(r io.Reader) error {
	dec := json.NewDecoder(r)
	for dec.More() {
		item := new(cacheItem)
		if err := dec.Decode(item); err != nil {
			return err
		}
		// Skip bad (or incompatible) records
		if item.Key.Question.Name == "" || item.Answer == nil {
			continue
		}
		c.addKey(item.Key, item.Answer)
	}
	return nil
}

func lruKeyFromQuery(q *dns.Msg) lruKey {
	key := lruKey{Question: q.Question[0]}

	edns0 := q.IsEdns0()
	if edns0 != nil {
		key.Do = edns0.Do()
		// See if we have a subnet option
		for _, opt := range edns0.Option {
			if subnet, ok := opt.(*dns.EDNS0_SUBNET); ok {
				key.Net = subnet.Address.String()
			}
		}
	}
	return key
}
