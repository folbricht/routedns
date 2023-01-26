package rdns

import (
	"errors"
	"expvar"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Cache stores results received from its upstream resolver for
// up to TTL seconds in memory.
type Cache struct {
	CacheOptions
	id       string
	resolver Resolver
	mu       sync.Mutex
	lru      *lruCache
	metrics  *CacheMetrics
}

type CacheMetrics struct {
	// Cache hit count.
	hit *expvar.Int
	// Cache miss count.
	miss *expvar.Int
	// Current cache entry count.
	entries *expvar.Int
}

var _ Resolver = &Cache{}

type CacheOptions struct {
	// Time period the cache garbage collection runs. Defaults to one minute if set to 0.
	GCPeriod time.Duration

	// Max number of responses to keep in the cache. Defaults to 0 which means no limit. If
	// the limit is reached, the least-recently used entry is removed from the cache.
	Capacity int

	// TTL to use for negative responses that do not have an SOA record, default 60
	NegativeTTL uint32

	// Allows control over the order of answer RRs in cached responses. Default is to keep
	// the order if nil.
	ShuffleAnswerFunc AnswerShuffleFunc

	// If enabled, will return NXDOMAIN for every name query under another name that is
	// already cached as NXDOMAIN. For example, if example.com is in the cache with
	// NXDOMAIN, a query for www.example.com will also immediately return NXDOMAIN.
	// See RFC8020.
	HardenBelowNXDOMAIN bool

	// Query name that will trigger a cache flush. Disabled if empty.
	FlushQuery string

	// If a query is received for a record with less that PrefetchTrigger TTL left, the
	// cache will send another query to upstream. The goal is to automatically refresh
	// the record in the cache.
	PrefetchTrigger uint32

	// Only records with at least PrefetchEligible seconds TTL are eligible to be prefetched.
	PrefetchEligible uint32
}

// NewCache returns a new instance of a Cache resolver.
func NewCache(id string, resolver Resolver, opt CacheOptions) *Cache {
	c := &Cache{
		CacheOptions: opt,
		id:           id,
		resolver:     resolver,
		lru:          newLRUCache(opt.Capacity),
		metrics: &CacheMetrics{
			hit:     getVarInt("cache", id, "hit"),
			miss:    getVarInt("cache", id, "miss"),
			entries: getVarInt("cache", id, "entries"),
		},
	}
	if c.GCPeriod == 0 {
		c.GCPeriod = time.Minute
	}
	if c.NegativeTTL == 0 {
		c.NegativeTTL = 60
	}
	go c.startGC(c.GCPeriod)
	return c
}

// Resolve a DNS query by first checking an internal cache for existing
// results
func (r *Cache) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	// While multiple questions in one DNS message is part of the standard,
	// it's not actually supported by servers. If we do get one of those,
	// just pass it through and bypass caching.
	if len(q.Question) > 1 {
		return r.resolver.Resolve(q, ci)
	}

	log := logger(r.id, q, ci)

	// Flush the cache if the magic query name is received and flushing is enabled.
	if r.FlushQuery != "" && r.FlushQuery == q.Question[0].Name {
		log.Info("flushing cache")
		r.flush()
		a := new(dns.Msg)
		return a.SetReply(q), nil
	}

	// Returned an answer from the cache if one exists
	a, prefetchEligible, ok := r.answerFromCache(q)
	if ok {
		log.Debug("cache-hit")
		r.metrics.hit.Add(1)

		// If prefetch is enabled and the TTL has fallen below the trigger time, send
		// a concurrent query upstream (to refresh the cached record)
		if prefetchEligible && r.CacheOptions.PrefetchTrigger > 0 {
			if min, ok := minTTL(a); ok && min < r.CacheOptions.PrefetchTrigger {
				prefetchQ := q.Copy()
				go func() {
					log.Debug("prefetching record")

					// Send the same query upstream
					prefetchA, err := r.resolver.Resolve(prefetchQ, ci)
					if err != nil || prefetchA == nil {
						return
					}

					// Don't cache truncated responses
					if prefetchA.Truncated {
						return
					}

					// If the prefetched record has a lower TTL than what we had already, there
					// is no point in storing it in the cache. This can happen when the upstream
					// resolver also uses caching.
					if prefetchAMin, ok := minTTL(prefetchA); !ok || prefetchAMin < min {
						return
					}

					// Put the upstream response into the cache and return it.
					r.storeInCache(prefetchQ, prefetchA)
				}()
			}
		}

		return a, nil
	}
	r.metrics.miss.Add(1)

	log.WithField("resolver", r.resolver.String()).Debug("cache-miss, forwarding")

	// Get a response from upstream
	a, err := r.resolver.Resolve(q.Copy(), ci)
	if err != nil || a == nil {
		return nil, err
	}

	// Don't cache truncated responses
	if a.Truncated {
		return a, nil
	}

	// Put the upstream response into the cache and return it. Need to store
	// a copy since other elements might modify the response, like the replacer.
	r.storeInCache(q, a.Copy())
	return a, nil
}

func (r *Cache) String() string {
	return r.id
}

// Returns an answer from the cache with it's TTL updated or false in case of a cache-miss.
func (r *Cache) answerFromCache(q *dns.Msg) (*dns.Msg, bool, bool) {
	var answer *dns.Msg
	var timestamp time.Time
	var prefetchEligible bool
	r.mu.Lock()
	if a := r.lru.get(q); a != nil {
		if r.ShuffleAnswerFunc != nil {
			r.ShuffleAnswerFunc(a.Msg)
		}
		answer = a.Copy()
		timestamp = a.timestamp
		prefetchEligible = a.prefetchEligible
	}
	r.mu.Unlock()

	// We couldn't find it in the cache, but a parent domain may already be with NXDOMAIN.
	// Return that instead if enabled.
	if answer == nil && r.HardenBelowNXDOMAIN {
		name := q.Question[0].Name
		newQ := q.Copy()
		fragments := strings.Split(name, ".")
		r.mu.Lock()
		for i := 1; i < len(fragments)-1; i++ {
			newQ.Question[0].Name = strings.Join(fragments[i:], ".")
			if a := r.lru.get(newQ); a != nil {
				if a.Rcode == dns.RcodeNameError {
					r.mu.Unlock()
					return nxdomain(q), false, true
				}
				break
			}
		}
		r.mu.Unlock()
	}

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
				r.evictFromCache(q)
				return nil, false, false
			}
			h.Ttl -= age
		}
	}

	return answer, prefetchEligible, true
}

func (r *Cache) storeInCache(query, answer *dns.Msg) {
	now := time.Now()

	// Prepare an item for the cache, without expiry for now
	item := &cacheAnswer{Msg: answer, timestamp: now}

	// Find the lowest TTL in the response, this determines the expiry for the whole answer in the cache.
	min, ok := minTTL(answer)

	// Calculate expiry for the whole record. Negative answers may not have a SOA to use the TTL from.
	switch answer.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError:
		if ok {
			item.expiry = now.Add(time.Duration(min) * time.Second)
			item.prefetchEligible = min > r.CacheOptions.PrefetchEligible
		} else {
			item.expiry = now.Add(time.Duration(r.NegativeTTL) * time.Second)
		}
	case dns.RcodeServerFailure:
		// According to RFC2308, a SERVFAIL response must not be cached for longer than 5 minutes.
		if r.NegativeTTL < 300 {
			item.expiry = now.Add(time.Duration(r.NegativeTTL) * time.Second)
		} else {
			item.expiry = now.Add(300 * time.Second)
		}
	default:
		return
	}

	// Store it in the cache
	r.mu.Lock()
	r.lru.add(query, item)
	r.mu.Unlock()
}

func (r *Cache) evictFromCache(queries ...*dns.Msg) {
	r.mu.Lock()
	for _, query := range queries {
		r.lru.delete(query)
	}
	r.mu.Unlock()
}

// Runs every period time and evicts all items from the cache that are
// older than max, regardless of TTL. Note that the cache can hold old
// records that are no longer valid. These will only be evicted once
// a new query for them is made (and TTL is too old) or when they are
// older than max.
func (r *Cache) startGC(period time.Duration) {
	for {
		time.Sleep(period)
		now := time.Now()
		var total, removed int
		r.mu.Lock()
		r.lru.deleteFunc(func(a *cacheAnswer) bool {
			if now.After(a.expiry) {
				removed++
				return true
			}
			return false
		})
		total = r.lru.size()
		r.mu.Unlock()

		r.metrics.entries.Set(int64(total))
		Log.WithFields(logrus.Fields{"total": total, "removed": removed}).Trace("cache garbage collection")
	}
}

// Flush the cache (reset to empty).
func (r *Cache) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lru.reset()
}

// Find the lowest TTL in all resource records (except OPT).
func minTTL(answer *dns.Msg) (uint32, bool) {
	var (
		min   uint32 = math.MaxUint32
		found bool
	)
	for _, rr := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, a := range rr {
			if _, ok := a.(*dns.OPT); ok {
				continue
			}
			h := a.Header()
			if h.Ttl < min {
				min = h.Ttl
				found = true
			}
		}
	}
	return min, found
}

// Shuffles the order of answer A/AAAA RRs. Used to allow for some control
// over the records in the cache.
type AnswerShuffleFunc func(*dns.Msg)

// Randomly re-order the A/AAAA answer records.
func AnswerShuffleRandom(msg *dns.Msg) {
	if len(msg.Answer) < 2 {
		return
	}
	// idx holds the indexes of A and AAAA records in the answer
	idx := make([]int, 0, len(msg.Answer))
	for i, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			idx = append(idx, i)
		}
	}
	rand.Shuffle(len(idx), func(i, j int) {
		msg.Answer[idx[i]], msg.Answer[idx[j]] = msg.Answer[idx[j]], msg.Answer[idx[i]]
	})
}

// Shift the answer A/AAAA record order in an answer by one.
func AnswerShuffleRoundRobin(msg *dns.Msg) {
	if len(msg.Answer) < 2 {
		return
	}
	var last dns.RR
	var dst int
	for i, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			if last == nil {
				last = rr
			} else {
				msg.Answer[dst] = rr
			}
			dst = i
		}
	}
	if last != nil {
		msg.Answer[dst] = last
	}
}
