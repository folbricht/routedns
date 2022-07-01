package rdns

import (
	"errors"
	"expvar"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

type CachePrefetch struct {
	CachePrefetchOptions
	id       string
	resolver Resolver
	mu       sync.Mutex
	metrics  *CachePrefetchMetrics
}


type CachePrefetchMetrics struct {
	// Cache hit count.
	domainEntries map[string]CachePrefetchEntry
}
type CachePrefetchEntry struct {
	// request hit count.
	hit 			  expvar.Int

	// 0 for no prefetching job
	// 1 for prefetching job is active
	// 2 for stopped by error
	prefetchingStatus expvar.Int
	// store the time to live
	ttl				  expvar.Int
	// fetching error count for discarding error prone fetches
	errorCount 		  expvar.Int
}

var _ Resolver = &CachePrefetch{}

type CachePrefetchOptions struct {
	//// Time of cache record ttl polling for record prefetch
	CacheTTLPollingCheckInterval time.Duration
	//// Min record time remaining check for expire
	MinRecordTimeRemainingPercent uint64

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
}

func NewCachePrefetch(id string, resolver Resolver, opt CachePrefetchOptions) *CachePrefetch {
	c := &CachePrefetch{
		CachePrefetchOptions: opt,
		id:                   id,
		resolver:             resolver,
		metrics: &CachePrefetchMetrics{
			domainEntries: map[string]CachePrefetchEntry{},
		},
	}
	if c.CacheTTLPollingCheckInterval == 0 {
		c.CacheTTLPollingCheckInterval = time.Minute
	}
	if c.RecordQueryHitsMin == 0 || c.RecordQueryHitsMin == 1 || c.RecordQueryHitsMin == -1 {
		// Set to hit after one record hit
		// fetch opportunistically
		c.RecordQueryHitsMin = 1
	}
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

	go r.requestAddPrefetchJob(q, ci)

	// Get a response from upstream
	a, err := r.resolver.Resolve(q.Copy(), ci)
	if err != nil || a == nil {
		return nil, err
	}

	// Put the upstream response into the cache and return it. Need to store
	// a copy since other elements might modify the response, like the replacer.
	return a, nil
}

func (r *CachePrefetch) String() string {
	return r.id
}
func (r *CachePrefetch) startCachePrefetch(q *dns.Msg, ci ClientInfo) {
	var maxNumberOfErrorsBeforeDiscardingPrefetchJob = int64(5)
	var qname = q.Question[0].Name

	for {
		var domainEntry = r.metrics.domainEntries[qname]
		if domainEntry.prefetchingStatus.Value() == 1 { // only prefetch if status is 1
			time.Sleep(r.CacheTTLPollingCheckInterval)
			a, err := r.resolver.Resolve(q.Copy(), ci)
			if err != nil || a == nil {
				Log.WithFields(logrus.Fields{"err": err}).Trace("prefetch error")
				domainEntry.errorCount.Add(1)
				r.metrics.domainEntries[qname] = domainEntry
			} else if domainEntry.errorCount.Value() > 0 {
				// reset error count after a successful request
				domainEntry.errorCount.Set(0)
				r.metrics.domainEntries[qname] = domainEntry
			}

			if domainEntry.errorCount.Value() >= maxNumberOfErrorsBeforeDiscardingPrefetchJob {
				// We don't want a bunch of error based prefetch jobs so after a certain number of errors we discard request
				// TODO discard error prone jobs @frank? How do I do that
				Log.WithFields(logrus.Fields{"errorCount": domainEntry.errorCount.Value(), "qname": qname}).Trace("prefetch disabled")
				domainEntry.prefetchingStatus.Set(2)
				r.metrics.domainEntries[qname] = domainEntry
			}
		} else if  domainEntry.prefetchingStatus.Value() == 2 {
			break
		}
	}
}
func (r *CachePrefetch) requestAddPrefetchJob(q *dns.Msg, ci ClientInfo) {
	if len(q.Question) < 1 {
		return
	}
	var qname = q.Question[0].Name
	r.metrics.domainEntries[qname] = CachePrefetchEntry{}
	var domainEntry = r.metrics.domainEntries[qname]
	if domainEntry.prefetchingStatus.Value() == 0  {
		domainEntry.hit.Add(1)
		if domainEntry.hit.Value() >= r.RecordQueryHitsMin {
			Log.WithFields(logrus.Fields{"query": qname}).Trace("prefetch job added")
			r.startCachePrefetch(q, ci)
			domainEntry.prefetchingStatus.Set(1)
		}

		r.metrics.domainEntries[qname] = domainEntry
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