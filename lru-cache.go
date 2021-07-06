package rdns

import (
	"time"

	"github.com/miekg/dns"
)

type lruCache struct {
	maxItems   int
	items      map[lruKey]*cacheItem
	head, tail *cacheItem
}

type cacheItem struct {
	key lruKey
	*cacheAnswer
	prev, next *cacheItem
}

type lruKey struct {
	question dns.Question
	net      string
}

type cacheAnswer struct {
	timestamp time.Time // Time the record was cached. Needed to adjust TTL
	expiry    time.Time // Time the record expires and should be removed
	*dns.Msg
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
	item := c.touch(key)
	if item != nil {
		return
	}
	// Add new item to the top of the linked list
	item = &cacheItem{
		key:         key,
		cacheAnswer: answer,
		next:        c.head.next,
		prev:        c.head,
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
		return item.cacheAnswer
	}
	return nil
}

// Shrink the cache down to the maximum number of items.
func (c *lruCache) resize() {
	if c.maxItems <= 0 { // no size limit
		return
	}
	drop := len(c.items) - c.maxItems
	for i := 0; i < drop; i++ {
		item := c.tail.prev
		item.prev.next = c.tail
		c.tail.prev = item.prev
		delete(c.items, item.key)
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
		if f(item.cacheAnswer) {
			item.prev.next = item.next
			item.next.prev = item.prev
			delete(c.items, item.key)
		}
		item = item.next
	}
}

func (c *lruCache) size() int {
	return len(c.items)
}

func lruKeyFromQuery(q *dns.Msg) lruKey {
	key := lruKey{question: q.Question[0]}

	edns0 := q.IsEdns0()
	if edns0 != nil {
		// See if we have a subnet option
		for _, opt := range edns0.Option {
			if subnet, ok := opt.(*dns.EDNS0_SUBNET); ok {
				key.net = subnet.Address.String()
			}
		}
	}
	return key
}
