package rdns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func blobTestKey() lruKey {
	return lruKey{
		Question: dns.Question{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Net:      "192.0.2.0",
		Do:       true,
		CD:       true,
		ECSMask:  24,
	}
}

func blobTestAnswer(t *testing.T) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion("a.example.com.", dns.TypeA)
	msg.Id = 4242
	rr, err := dns.NewRR("a.example.com. 300 IN A 192.0.2.7")
	require.NoError(t, err)
	msg.Answer = []dns.RR{rr}
	return msg
}

// Every field of the key has to take part in the comparison. Leaving one out
// would serve a response stored under a different question, and the DO and CD
// bits are the easiest to miss because they share a byte.
func TestBlobKeyComparisonCoversEveryField(t *testing.T) {
	key := blobTestKey()
	blob, err := encodeCacheAnswerBlob(key, &cacheAnswer{Msg: blobTestAnswer(t)})
	require.NoError(t, err)
	require.True(t, blobMatchesKey(blob, key), "the key it was stored under must match")

	differs := map[string]func(*lruKey){
		// same length, different content, so this can't pass on a length check
		"name":     func(k *lruKey) { k.Question.Name = "z.example.com." },
		"name len": func(k *lruKey) { k.Question.Name = "aa.example.com." },
		"qtype":    func(k *lruKey) { k.Question.Qtype = dns.TypeAAAA },
		"qclass":   func(k *lruKey) { k.Question.Qclass = dns.ClassCHAOS },
		"net":      func(k *lruKey) { k.Net = "198.51.100.0" },
		"net len":  func(k *lruKey) { k.Net = "10.0.0.0" },
		"no net":   func(k *lruKey) { k.Net = "" },
		"do":       func(k *lruKey) { k.Do = false },
		"cd":       func(k *lruKey) { k.CD = false },
		"ecs mask": func(k *lruKey) { k.ECSMask = 16 },
	}
	for name, mutate := range differs {
		t.Run(name, func(t *testing.T) {
			other := blobTestKey()
			mutate(&other)
			require.False(t, blobMatchesKey(blob, other),
				"a key differing only in %s must not match", name)
		})
	}
}

// The prefetch-eligible flag is metadata, not part of the key, so it must not
// affect whether an entry is found.
func TestBlobKeyIgnoresMetadata(t *testing.T) {
	key := blobTestKey()
	for _, eligible := range []bool{false, true} {
		blob, err := encodeCacheAnswerBlob(key, &cacheAnswer{Msg: blobTestAnswer(t), PrefetchEligible: eligible})
		require.NoError(t, err)
		require.True(t, blobMatchesKey(blob, key))
		require.Equal(t, eligible, blobPrefetchEligible(blob))
	}
}

func TestBlobRoundTrip(t *testing.T) {
	key := blobTestKey()
	msg := blobTestAnswer(t)
	ts := time.Date(2026, 8, 15, 9, 30, 0, 123456789, time.UTC)

	blob, err := encodeCacheAnswerBlob(key, &cacheAnswer{
		Timestamp:        ts,
		Expiry:           ts.Add(time.Hour),
		PrefetchEligible: true,
		Msg:              msg,
	})
	require.NoError(t, err)

	require.Equal(t, key, blobKey(blob))
	require.Equal(t, ts.UnixNano(), blobTimestamp(blob))
	require.Equal(t, ts.Add(time.Hour).UnixNano(), blobExpiry(blob))
	require.True(t, blobPrefetchEligible(blob))

	got := new(dns.Msg)
	require.NoError(t, got.Unpack(blobMessage(blob)))
	require.Equal(t, mustPack(t, msg), mustPack(t, got))
}

// A key with no ECS option is the common case and has an empty Net.
func TestBlobRoundTripWithoutECS(t *testing.T) {
	key := lruKey{Question: dns.Question{Name: "plain.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg := new(dns.Msg)
	msg.SetQuestion("plain.example.com.", dns.TypeA)

	blob, err := encodeCacheAnswerBlob(key, &cacheAnswer{Msg: msg})
	require.NoError(t, err)
	require.Equal(t, key, blobKey(blob))
	require.True(t, blobMatchesKey(blob, key))
}

// Both lengths live in one byte each, so a name that can't be represented has
// to be refused rather than silently truncated into a key that collides.
func TestBlobRejectsOversizedName(t *testing.T) {
	long := strings.Repeat("a", 250) + "." + strings.Repeat("b", 10) + "."
	key := lruKey{Question: dns.Question{Name: long, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg := new(dns.Msg)
	msg.SetQuestion("short.example.com.", dns.TypeA)

	_, err := encodeCacheAnswerBlob(key, &cacheAnswer{Msg: msg})
	require.Error(t, err)
	require.Contains(t, err.Error(), "too long")
}

// Store encodes the message and must not hold on to it, and Lookup must hand
// back one the caller owns. Both directions matter: Cache.Resolve now passes
// the same message it returns to its caller.
func TestMemoryBackendDoesNotShareMessages(t *testing.T) {
	b := NewMemoryBackend(MemoryBackendOptions{GCPeriod: time.Hour})
	defer b.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a := new(dns.Msg)
	a.SetReply(q)
	rr, err := dns.NewRR("example.com. 3600 IN A 192.0.2.1")
	require.NoError(t, err)
	a.Answer = []dns.RR{rr}

	now := time.Now()
	b.Store(q, &cacheAnswer{Msg: a, Timestamp: now, Expiry: now.Add(time.Hour)})

	// Whatever happens to the message afterwards must not reach the cache.
	a.Answer[0].(*dns.A).A = net.IP{10, 0, 0, 1}
	a.Answer = append(a.Answer, rr)
	a.Rcode = dns.RcodeServerFailure

	got, _, ok := b.Lookup(q)
	require.True(t, ok)
	require.Equal(t, dns.RcodeSuccess, got.Rcode)
	require.Len(t, got.Answer, 1)
	require.Equal(t, "192.0.2.1", got.Answer[0].(*dns.A).A.String())

	// And the message handed out is the caller's to modify.
	got.Answer[0].(*dns.A).A = net.IP{172, 16, 0, 1}
	again, _, ok := b.Lookup(q)
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", again.Answer[0].(*dns.A).A.String())
}

// Lookup takes only the blob reference under the lock and decodes it after
// releasing, which is only safe because a stored blob is never modified. A
// concurrent Store replaces the slice rather than writing into it.
func TestMemoryBackendConcurrentStoreAndLookup(t *testing.T) {
	b := NewMemoryBackend(MemoryBackendOptions{GCPeriod: time.Hour})
	defer b.Close()

	const names = 8
	queries := make([]*dns.Msg, names)
	answers := make([]*dns.Msg, names)
	for i := range names {
		name := fmt.Sprintf("host%d.example.com.", i)
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		a := new(dns.Msg)
		a.SetReply(q)
		rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN A 192.0.2.%d", name, i+1))
		require.NoError(t, err)
		a.Answer = []dns.RR{rr}
		queries[i], answers[i] = q, a
	}

	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			now := time.Now()
			for range 500 {
				i := w % names
				b.Store(queries[i], &cacheAnswer{
					Msg: answers[i].Copy(), Timestamp: now, Expiry: now.Add(time.Hour),
				})
				if got, _, ok := b.Lookup(queries[i]); ok {
					// whatever is found must be the record for that name
					require.Equal(t, queries[i].Question[0].Name, got.Question[0].Name)
				}
			}
		}()
	}
	wg.Wait()
}
