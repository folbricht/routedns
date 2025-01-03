package rdns

import (
	"errors"
	"expvar"
	"math"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Cache stores results received from its upstream resolver for
// up to TTL seconds in memory.
type Cache struct {
	CacheOptions
	id       string
	resolver Resolver
	metrics  *CacheMetrics
	backend  CacheBackend
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
	//
	// Deprecated: Pass a configured cache backend instead.
	GCPeriod time.Duration

	// Max number of responses to keep in the cache. Defaults to 0 which means no limit. If
	// the limit is reached, the least-recently used entry is removed from the cache.
	//
	// Deprecated: Pass a configured cache backend instead.
	Capacity int

	// TTL to use for negative responses that do not have an SOA record, default 60
	NegativeTTL uint32

	// Define upper limits on cache TTLs based on RCODE, regardless of SOA. For example this
	// allows settings a limit on how long NXDOMAIN (code 3) responses can be kept in the cache.
	CacheRcodeMaxTTL map[int]uint32

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

	// Cache backend used to store records.
	Backend CacheBackend
}

type CacheBackend interface {
	Store(query *dns.Msg, item *cacheAnswer)

	// Lookup a cached response
	Lookup(q *dns.Msg) (answer *dns.Msg, prefetchEligible bool, ok bool)

	// Return the number of items in the cache
	Size() int

	// Flush all records in the store
	Flush()

	Close() error
}

// NewCache returns a new instance of a Cache resolver.
func NewCache(id string, resolver Resolver, opt CacheOptions) *Cache {
	c := &Cache{
		CacheOptions: opt,
		id:           id,
		resolver:     resolver,
		metrics: &CacheMetrics{
			hit:     getVarInt("cache", id, "hit"),
			miss:    getVarInt("cache", id, "miss"),
			entries: getVarInt("cache", id, "entries"),
		},
	}
	if c.NegativeTTL == 0 {
		c.NegativeTTL = 60
	}
	if opt.Backend == nil {
		opt.Backend = NewMemoryBackend(MemoryBackendOptions{
			Capacity: opt.Capacity,
			GCPeriod: opt.GCPeriod,
		})
	}
	c.backend = opt.Backend

	// Regularly query the cache size and emit metrics
	go func() {
		for {
			time.Sleep(time.Minute)
			total := c.backend.Size()
			c.metrics.entries.Set(int64(total))
		}
	}()

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
		r.backend.Flush()
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

	log.With("resolver", r.resolver.String()).Debug("cache-miss, forwarding")

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
	a, prefetchEligible, ok := r.backend.Lookup(q)
	if ok {
		if r.ShuffleAnswerFunc != nil {
			r.ShuffleAnswerFunc(a)
		}
		return a, prefetchEligible, true
	}

	// We couldn't find it in the cache, but a parent domain may already be with NXDOMAIN.
	// Return that instead if enabled.
	if r.HardenBelowNXDOMAIN {
		name := q.Question[0].Name
		newQ := q.Copy()
		fragments := strings.Split(name, ".")
		for i := 1; i < len(fragments)-1; i++ {
			newQ.Question[0].Name = strings.Join(fragments[i:], ".")
			if a, _, ok := r.backend.Lookup(newQ); ok {
				if a.Rcode == dns.RcodeNameError {
					return nxdomain(q), false, true
				}
				break
			}
		}
	}

	return nil, false, false
}

func (r *Cache) storeInCache(query, answer *dns.Msg) {
	now := time.Now()

	// Prepare an item for the cache, without expiry for now
	item := &cacheAnswer{Msg: answer, Timestamp: now}

	// Find the lowest TTL in the response, this determines the expiry for the whole answer in the cache.
	min, ok := minTTL(answer)

	// Calculate expiry for the whole record. Negative answers may not have a SOA to use the TTL from.
	switch answer.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError:
		if ok {
			item.Expiry = now.Add(time.Duration(min) * time.Second)
			item.PrefetchEligible = min > r.CacheOptions.PrefetchEligible
		} else {
			item.Expiry = now.Add(time.Duration(r.NegativeTTL) * time.Second)
		}
	case dns.RcodeServerFailure:
		// According to RFC2308, a SERVFAIL response must not be cached for longer than 5 minutes.
		if r.NegativeTTL < 300 {
			item.Expiry = now.Add(time.Duration(r.NegativeTTL) * time.Second)
		} else {
			item.Expiry = now.Add(300 * time.Second)
		}
	default:
		return
	}

	// Set the RCODE-based limit if one was configured
	if rcodeLimit, ok := r.CacheOptions.CacheRcodeMaxTTL[answer.Rcode]; ok {
		limit := now.Add(time.Duration(rcodeLimit) * time.Second)
		if item.Expiry.After(limit) {
			item.Expiry = limit
		}
	}

	// Store it in the cache
	r.backend.Store(query, item)
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

// Round Robin shuffling requires keeping state as it's operating on copies
// of DNS messages so the number of shift operations needs to be remembered.
type rrShuffleRecord struct {
	reads  uint64
	expiry time.Time
}

var (
	rrShuffleState map[lruKey]*rrShuffleRecord
	rrShuffleOnce  sync.Once
	rrShuffleMu    sync.RWMutex
)

// Shift the answer A/AAAA record order in an answer by one.
func AnswerShuffleRoundRobin(msg *dns.Msg) {
	if len(msg.Answer) < 2 {
		return
	}
	rrShuffleOnce.Do(func() {
		rrShuffleState = make(map[lruKey]*rrShuffleRecord)

		// Start a cleanup job
		go func() {
			for {
				time.Sleep(30 * time.Second)
				rrShuffleMu.RLock()

				// Build a list of expired items
				var toRemove []lruKey
				for k, v := range rrShuffleState {
					now := time.Now()
					if now.After(v.expiry) {
						toRemove = append(toRemove, k)
					}
				}
				rrShuffleMu.RUnlock()

				// Remove the expired items
				rrShuffleMu.Lock()
				for _, k := range toRemove {
					delete(rrShuffleState, k)
				}
				rrShuffleMu.Unlock()
			}
		}()
	})

	// Lookup how often the results were shifted previously
	key := lruKeyFromQuery(msg)
	rrShuffleMu.RLock()
	rec, ok := rrShuffleState[key]
	rrShuffleMu.RUnlock()
	var shiftBy uint64
	if ok {
		shiftBy = atomic.AddUint64(&rec.reads, 1)
	} else {
		ttl, ok := minTTL(msg)
		if !ok {
			return
		}
		rec = &rrShuffleRecord{
			expiry: time.Now().Add(time.Duration(ttl) * time.Second),
		}
		rrShuffleMu.Lock()
		rrShuffleState[key] = rec
		rrShuffleMu.Unlock()
	}

	// Build a list of pointers to A/AAAA records in the message
	var aRecords []*dns.RR
	for i, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			aRecords = append(aRecords, &msg.Answer[i])
		}
	}
	if len(aRecords) < 2 {
		return
	}

	// Rotate the A/AAAA record pointers
	shiftBy %= uint64(len(aRecords))
	shiftBy++

	for i := uint64(0); i < shiftBy; i++ {
		last := *aRecords[len(aRecords)-1]
		for j := len(aRecords) - 1; j > 0; j-- {
			*aRecords[j] = *aRecords[j-1]
		}
		*aRecords[0] = last
	}
}
