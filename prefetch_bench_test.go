package rdns

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// answerResolver returns a valid, cacheable response (success, untruncated,
// TTL >= 2) so that Prefetch.Resolve exercises its cache read/write path
// rather than bailing out early.
type answerResolver struct{}

func (answerResolver) Resolve(q *dns.Msg, _ ClientInfo) (*dns.Msg, error) {
	a := new(dns.Msg)
	a.SetReply(q)
	if len(q.Question) > 0 {
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.1")
		a.Answer = append(a.Answer, rr)
	}
	return a, nil
}

func (answerResolver) String() string { return "answerResolver()" }

// benchPrefetch drives Prefetch.Resolve concurrently across a spread of
// distinct query names. The number of distinct names controls how much the
// goroutines collide on the same cache keys/shards. shards selects the cache
// sharding: 1 means a single shard (the pre-change behavior), >1 forces that
// many shards (the post-change behavior uses GOMAXPROCS).
func benchPrefetch(b *testing.B, distinctNames int, shards uint) {
	// Build a Prefetch but override the shard count so we can compare
	// sharded vs unsharded independently of GOMAXPROCS.
	r := newPrefetchWithShards("bench", answerResolver{}, PrefetchOptions{
		PrefetchThreshold: 1, // cache on the first hit so writes happen every call
		PrefetchMaxItems:  distinctNames * 2,
		PrefetchCacheSize: distinctNames * 6,
	}, shards)

	names := make([]string, distinctNames)
	for i := range names {
		names[i] = fmt.Sprintf("host%d.example.com.", i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i uint64
		q := new(dns.Msg)
		for pb.Next() {
			name := names[atomic.AddUint64(&i, 1)%uint64(distinctNames)]
			q.SetQuestion(name, dns.TypeA)
			if _, err := r.Resolve(q, ClientInfo{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Few distinct names => heavy contention on the same shards.
func BenchmarkPrefetchHotKeysUnsharded(b *testing.B) { benchPrefetch(b, 8, 1) }
func BenchmarkPrefetchHotKeysSharded(b *testing.B) {
	benchPrefetch(b, 8, uint(runtime.GOMAXPROCS(0)))
}

// Many distinct names => writes spread across keys (and shards).
func BenchmarkPrefetchSpreadUnsharded(b *testing.B) { benchPrefetch(b, 4096, 1) }
func BenchmarkPrefetchSpreadSharded(b *testing.B) {
	benchPrefetch(b, 4096, uint(runtime.GOMAXPROCS(0)))
}
