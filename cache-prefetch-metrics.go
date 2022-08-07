package rdns

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"sync"
)

type CachePrefetchMetrics struct {
	// Cache hit count.
	items map[cachePrefetchKey]*CachePrefetchEntry
	// TODO item limit param
	maxItems int
	errorCountMax int16
	hitMin int64
	mu       sync.Mutex
}

// 0 for no prefetching job
// 1 for prefetching job is active
// 2 for stopped by error
type PrefetchState int

const (
	PrefetchStateNone   = iota
	PrefetchStateActive
	PrefetchStateOther
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
	c.mu.Lock()
	if c.addItem(query) == PrefetchStateNone {
		qname := qName(query)
		Log.WithFields(logrus.Fields{"qname": qname}).Trace("query prefetch hit")
		c.addHit(query)
	}
	c.mu.Unlock()
}
func (c *CachePrefetchMetrics) addItem(query *dns.Msg) PrefetchState {
	key := getDomainKey(query)
	item := c.touch(key)
	if item != nil {
		return item.prefetchState
	}
	// Add new item to the top of the linked list
	if len(c.items) > c.maxItems {
		Log.WithFields(logrus.Fields{"maxItems": c.maxItems, "items-count": len(c.items)}).Trace("prefetch item cache full")
		return PrefetchStateOther

	}

	item = NewCachePrefetchEntry(key)
	c.items[key] = item
	return item.prefetchState
}
func (c *CachePrefetchMetrics) addHit(query *dns.Msg) {
	c.mu.Lock()
	key := getDomainKey(query)
	item := c.items[key]
	item.hit ++
	if item.hit >= c.hitMin {
		item.prefetchState = PrefetchStateActive
		item.msg = query
		Log.WithFields(logrus.Fields{"prefetchState": item.prefetchState}).Trace("prefetch item state changed")
	}
	c.items[key] = item
	c.mu.Unlock()
}
func (c *CachePrefetchMetrics) addError(query *dns.Msg) {
	c.mu.Lock()
	key := getDomainKey(query)
	item := c.items[key]
	item.errorCount++
	if item.errorCount > c.errorCountMax {
		item.prefetchState = PrefetchStateOther
		Log.WithFields(logrus.Fields{"prefetchState": item.prefetchState}).Trace("prefetch item state changed")
	}
	c.items[key] = item
	c.mu.Unlock()
}
func (c *CachePrefetchMetrics) resetError(query *dns.Msg) {
	c.mu.Lock()
	key := getDomainKey(query)
	item := c.items[key]
	item.errorCount = 0
	c.items[key] = item
	Log.WithFields(logrus.Fields{"key": item.key}).Trace("prefetch item error count reset")
	c.mu.Unlock()
}
// Loads a cache item
func (c *CachePrefetchMetrics) touch(key cachePrefetchKey) *CachePrefetchEntry {
	item := c.items[key]
	return item
}
func getDomainKey(q *dns.Msg) cachePrefetchKey {
	if (q == nil) || len(q.Question) < 1 {
		return cachePrefetchKey{}
	}
	qname := qName(q)
	qtype := qType(q)
	key := cachePrefetchKey{qname, qtype}
	return key
}