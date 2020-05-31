package rdns

import (
	"time"

	"github.com/miekg/dns"
)

type lruCache struct {
	maxItems   int
	items      map[dns.Question]*cacheItem
	head, tail *cacheItem
}

type cacheItem struct {
	*cacheAnswer
	prev, next *cacheItem
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
		items:    make(map[dns.Question]*cacheItem),
		head:     head,
		tail:     tail,
	}
}

func (c *lruCache) add(answer *cacheAnswer) {
	question := answer.Question[0]
	item := c.touch(question)
	if item != nil {
		return
	}
	// Add new item to the top of the linked list
	item = &cacheItem{
		cacheAnswer: answer,
		next:        c.head.next,
		prev:        c.head,
	}
	c.head.next.prev = item
	c.head.next = item
	c.items[question] = item
	c.resize()
}

// Loads a cache item and puts it to the top of the queue (most recent).
func (c *lruCache) touch(question dns.Question) *cacheItem {
	item := c.items[question]
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

func (c *lruCache) delete(question dns.Question) {
	item := c.items[question]
	if item == nil {
		return
	}
	item.prev.next = item.next
	item.next.prev = item.prev
	delete(c.items, item.Question[0])
}

func (c *lruCache) get(question dns.Question) *cacheAnswer {
	item := c.touch(question)
	if item != nil {
		return item.cacheAnswer
	}
	return nil
}

// Shrink the cache down to the maximum number of itmes.
func (c *lruCache) resize() {
	if c.maxItems <= 0 { // no size limit
		return
	}
	drop := len(c.items) - c.maxItems
	for i := 0; i < drop; i++ {
		item := c.tail.prev
		item.prev.next = c.tail
		c.tail.prev = item.prev
		delete(c.items, item.Question[0])
	}
}

// Iterate over the cached answers and call the provided function. If it
// returns true, the item is deleted from the cache.
func (c *lruCache) deleteFunc(f func(*cacheAnswer) bool) {
	item := c.head.next
	for item != c.tail {
		if f(item.cacheAnswer) {
			item.prev.next = item.next
			item.next.prev = item.prev
			delete(c.items, item.Question[0])
		}
		item = item.next
	}
}

func (c *lruCache) size() int {
	return len(c.items)
}
