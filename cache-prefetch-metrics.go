package rdns

import (
	"github.com/miekg/dns"
)

type CachePrefetchMetrics struct {
	// Cache hit count.
	items map[cachePrefetchKey]*CachePrefetchEntry
	// TODO item limit param
	maxItems int
	errorCountMax int16
	hitMin int64
}

// 0 for no prefetching job
// 1 for prefetching job is active
// 2 for stopped by error
type PrefetchState int

const (
	PrefetchStateNone   = iota
	PrefetchStateActive = 1
	PrefetchStateOther  = 2
)

type cachePrefetchKey struct {
	qname string
	qtype string
}

type CachePrefetchEntry struct {
	// request hit count.
	hit int64

	prefetchState PrefetchState
	// msg to refetch
	msg *dns.Msg
	//ttl      int
	// fetching error count for discarding error prone fetches
	errorCount int16
	key        cachePrefetchKey
}

func NewCachePrefetchEntry(index cachePrefetchKey) *CachePrefetchEntry {
	return &CachePrefetchEntry{
		hit:           0,
		prefetchState: PrefetchStateNone,
		msg:           nil,
		errorCount:    0,
		key:           index,
	}
}

func NewCachePrefetchMetrics(capacity int, errorCountMax int16, hitMin int64) CachePrefetchMetrics {
		return CachePrefetchMetrics{
		maxItems: capacity,
		items:    make(map[cachePrefetchKey]*CachePrefetchEntry),
		errorCountMax: errorCountMax,
		hitMin: hitMin,

	}
}
func (c *CachePrefetchMetrics) processQuery(query *dns.Msg) {
	if c.addItem(query) == PrefetchStateNone {
		c.addHit(query)
	}
}
func (c *CachePrefetchMetrics) addItem(query *dns.Msg) PrefetchState {
	key := c.getDomainKey(query)
	item := c.touch(key)
	if item != nil {
		return item.prefetchState
	}
	// Add new item to the top of the linked list
	if len(c.items) > c.maxItems {
		return PrefetchStateOther
	}

	item = NewCachePrefetchEntry(key)
	c.items[key] = item
	return item.prefetchState
}
func (c *CachePrefetchMetrics) addHit(query *dns.Msg) {
	key := c.getDomainKey(query)
	item := c.items[key]
	item.hit ++
	if item.hit >= c.hitMin {
		item.prefetchState = PrefetchStateActive
	}
	c.items[key] = item
}
func (c *CachePrefetchMetrics) addError(query *dns.Msg) {
	key := c.getDomainKey(query)
	item := c.items[key]
	item.errorCount++
	if item.errorCount > c.errorCountMax {
		item.prefetchState = PrefetchStateOther
	}
	c.items[key] = item
}
func (c *CachePrefetchMetrics) resetError(query *dns.Msg) {
	key := c.getDomainKey(query)
	item := c.items[key]
	item.errorCount = 0
	c.items[key] = item
}
// Loads a cache item
func (c *CachePrefetchMetrics) touch(key cachePrefetchKey) *CachePrefetchEntry {
	item := c.items[key]
	if item == nil {
		return nil
	}
	return item
}
// GET KEYS
func (r *CachePrefetchEntry) getDomainKey(q *dns.Msg) cachePrefetchKey {
	if (q == nil) || len(q.Question) < 1 {
		return cachePrefetchKey{}
	}
	qname := qName(q)
	qtype := qType(q)
	key := cachePrefetchKey{qname, qtype}
	return key
}

func (c *CachePrefetchMetrics) getDomainKey(q *dns.Msg) cachePrefetchKey {
	if (q == nil) || len(q.Question) < 1 {
		return cachePrefetchKey{}
	}
	qname := qName(q)
	qtype := qType(q)
	key := cachePrefetchKey{qname, qtype}
	return key
}
