package rdns

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"
	"time"
)

type CachePrefetch struct {
	CachePrefetchOptions
	id       string
	resolver Resolver
	mu       sync.Mutex
	metrics  CachePrefetchMetrics
}

type CachePrefetchMetrics struct {
	// Cache hit count.
	domainEntries map[string]CachePrefetchEntry
	// TODO item limit param
	maxItems   int
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

type CachePrefetchEntry struct {
	// request hit count.
	hit                int64

	prefetchState     PrefetchState
	// msg to refetch
	msg               *dns.Msg
	//ttl      int
	// fetching error count for discarding error prone fetches
	errorCount         int16
}
func (r *CachePrefetchEntry) initItem() CachePrefetchEntry {
	return CachePrefetchEntry{
		hit: 0,
		prefetchState: PrefetchStateNone,
		msg: nil,
		errorCount: 0,
	}
}
func (r *CachePrefetchEntry) update(cachePrefetchEntry CachePrefetchEntry) CachePrefetchEntry {
	return cachePrefetchEntry
}
var _ Resolver = &CachePrefetch{}

type CachePrefetchOptions struct {
	//// Time of cache record ttl polling for record prefetch
	CacheTTLPollingCheckInterval time.Duration
	//// Min record time remaining check for expire
	MinRecordTimeRemainingPercent uint64
	MaxNumberOfErrorsBeforeDiscardingPrefetchJob int16
	// Number of hits a record gets before prefetch on a record is started
	RecordQueryHitsMin int64
	// Max number of responses to check in the cache. Defaults to 0 which means no limit. If
	// the limit is reached, the least-recently used entry is removed from the cache.
	//TODO
	//RecordCheckCapacity uint32
	// Cache to check records from
	//CacheResolver Cache
	// Allows control over the order of answer RRs in cached responses. Default is to keep
	// the order if nil.
	// TODO
	//ShuffleAnswerFunc AnswerShuffleFunc
	PrefetchSize int
}

func NewCachePrefetch(id string, resolver Resolver, opt CachePrefetchOptions) *CachePrefetch {
	c := &CachePrefetch{
		CachePrefetchOptions: opt,
		id:                   id,
		resolver:             resolver,
		metrics: CachePrefetchMetrics{
			domainEntries: map[string]CachePrefetchEntry{},
			maxItems: 0,
		},
	}
	if c.MaxNumberOfErrorsBeforeDiscardingPrefetchJob == 0 {
		c.MaxNumberOfErrorsBeforeDiscardingPrefetchJob = int16(5)
	}

	if c.CacheTTLPollingCheckInterval == 0 {
		c.CacheTTLPollingCheckInterval = time.Minute
	}
	if c.RecordQueryHitsMin == 0 || c.RecordQueryHitsMin == 1 || c.RecordQueryHitsMin == -1 {
		// Set to hit after one record hit
		// fetch opportunistically
		c.RecordQueryHitsMin = 1
	}
	go c.startCachePrefetchJobs()
	return c
}

func (r *CachePrefetch) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {

	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	// While multiple questions in one DNS message is part of the standard,
	// it's not actually supported by servers. If we do get one of those,
	// just pass it through and bypass caching.
	if len(q.Question) > 1 {
		return r.resolver.Resolve(q, ci)
	}



	// Get a response from upstream
	a, err := r.resolver.Resolve(q.Copy(), ci)
	if err != nil || a == nil {
		return nil, err
	}

	r.requestAddPrefetchJob(q)

	// Put the upstream response into the cache and return it. Need to store
	// a copy since other elements might modify the response, like the replacer.
	return a, nil
}

func (r *CachePrefetch) String() string {
	return r.id
}
func (r *CachePrefetch) startCachePrefetchJobs() {
	Log.WithFields(logrus.Fields{"id": r.id}).Trace("starting prefetching job")
	for {
		time.Sleep(r.CacheTTLPollingCheckInterval)
		domainEntriesLength := len(r.metrics.domainEntries)
		if domainEntriesLength > 0 {
			for index, entry := range r.metrics.domainEntries {
				Log.WithFields(logrus.Fields{"index": index, "total": domainEntriesLength}).Trace("prefetch")
				r.startCachePrefetchJob(entry, index)
			}
		}
	}
}
func (r *CachePrefetch) startCachePrefetchJob(domainEntry CachePrefetchEntry, index string) {
	q := domainEntry.msg
	if (q == nil) || len(q.Question) < 1 {
		return
	}

	qname := qName(q)
	qtype := qType(q)

	if domainEntry.prefetchState == PrefetchStateActive { // only prefetch if status is 1
		r.mu.Lock()
		Log.WithFields(logrus.Fields{"qname": qname, "qtype": qtype}).Trace("prefetch request started")
		var ci ClientInfo
		a, err := r.resolver.Resolve(q.Copy(), ci)

		if err != nil || a == nil {
			Log.WithFields(logrus.Fields{"err": err}).Trace("prefetch error")

			domainEntry.errorCount++
		} else {
			if domainEntry.errorCount > 0 {
				// reset error count after a successful request
				domainEntry.errorCount = 0

				Log.WithFields(logrus.Fields{"qname": qname, "qtype": qtype}).Trace("query reset error count")
			}
			Log.WithFields(logrus.Fields{ "qname": qname, "qtype": qtype}).Debug("query prefetched")
		}


		if domainEntry.errorCount >= r.MaxNumberOfErrorsBeforeDiscardingPrefetchJob {
			// We don't want a bunch of error based prefetch jobs so after a certain number of errors we discard request
			// TODO discard error prone jobs @frank? How do I do that

			Log.WithFields(logrus.Fields{"errorCount": domainEntry.errorCount, "qname": qname}).Trace("prefetch disabled")
			domainEntry.prefetchState = PrefetchStateOther
			// Discard error prone dns messages because they will not be used again
			domainEntry.msg = nil

		}
		r.metrics.domainEntries[index].update(domainEntry)
		r.mu.Unlock()
	}

}
func (r *CachePrefetch) getDomainKey(q *dns.Msg) string {
	if (q == nil) || len(q.Question) < 1 {
		return ""
	}
	qname := qName(q)
	qtype := qType(q)
	str := []string{qname, qtype}
	var domainKey = strings.Join(str, "-")
	return domainKey
}
func (r *CachePrefetch) requestAddPrefetchJob(q *dns.Msg) {
	if (q == nil) || len(q.Question) < 1 {
		return
	}
	domainKey := r.getDomainKey(q)

	if domainKey == "" {
		return
	}
	domainEntry, found := r.metrics.domainEntries[domainKey]
	// Don't excide the limit of entries
	if r.PrefetchSize > len(r.metrics.domainEntries) && !found {
		return
	} else if !found {
		r.mu.Lock()
		r.metrics.domainEntries[domainKey].initItem()
		r.mu.Unlock()
	}
	qname := qName(q)
	qtype := qType(q)

	if domainEntry.prefetchState == PrefetchStateNone {
		r.mu.Lock()
		domainEntry.hit++
		if domainEntry.hit >= r.RecordQueryHitsMin {
			Log.WithFields(logrus.Fields{"query": qname, "qtype": qtype}).Debug("prefetch job requested")
			domainEntry.prefetchState = PrefetchStateActive
			domainEntry.msg = q
		}
		r.metrics.domainEntries[domainKey].update(domainEntry)
		r.mu.Unlock()

	}


}

func (r *CachePrefetch) isRecordTTLExpiring(opt CachePrefetchOptions, a *cacheAnswer) float32 {

	var ttl = a.Answer[0].Header().Ttl
	now := time.Now()
	var beforeExpiry = now.Before(a.expiry)
	Log.WithFields(logrus.Fields{"query": a.Answer[0].Header().Name}).Trace("cache check prefetch")
	if beforeExpiry {
		var secondsBeforeExpiry = uint64(a.expiry.Sub(now).Seconds())
		var expiryTimeLeftPercent = uint64(ttl) / secondsBeforeExpiry
		if opt.MinRecordTimeRemainingPercent == 0 {
			// fetch opportunistically
			return 1
		}
		if opt.MinRecordTimeRemainingPercent < expiryTimeLeftPercent {
			Log.WithFields(logrus.Fields{"err": 1}).Trace("cache err prefetch")
			return 1
		} else {
			Log.WithFields(logrus.Fields{"err": 0}).Trace("cache err prefetch")
			return 0
		}
	} else {
		Log.WithFields(logrus.Fields{"err": -1}).Trace("cache err prefetch")
		// -1 is expired cannot prefetch
		return -1
	}
}
