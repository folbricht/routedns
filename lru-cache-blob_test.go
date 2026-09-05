package rdns

import (
	"fmt"
	"math"
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
	blob, err := newCacheBlob(key, &cacheAnswer{Msg: blobTestAnswer(t)})
	require.NoError(t, err)
	require.True(t, blob.matchesKey(key), "the key it was stored under must match")

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
			require.False(t, blob.matchesKey(other),
				"a key differing only in %s must not match", name)
		})
	}
}

// The prefetch-eligible flag is metadata, not part of the key, so it must not
// affect whether an entry is found.
func TestBlobKeyIgnoresMetadata(t *testing.T) {
	key := blobTestKey()
	for _, eligible := range []bool{false, true} {
		blob, err := newCacheBlob(key, &cacheAnswer{Msg: blobTestAnswer(t), PrefetchEligible: eligible})
		require.NoError(t, err)
		require.True(t, blob.matchesKey(key))
		require.Equal(t, eligible, blob.prefetchEligible())
	}
}

func TestBlobRoundTrip(t *testing.T) {
	key := blobTestKey()
	msg := blobTestAnswer(t)
	ts := time.Date(2026, 8, 15, 9, 30, 0, 123456789, time.UTC)

	blob, err := newCacheBlob(key, &cacheAnswer{
		Timestamp:        ts,
		Expiry:           ts.Add(time.Hour),
		PrefetchEligible: true,
		Msg:              msg,
	})
	require.NoError(t, err)

	require.Equal(t, key, blob.key())
	require.Equal(t, ts.UnixNano(), blob.timestamp())
	require.Equal(t, ts.Add(time.Hour).UnixNano(), blob.expiry())
	require.True(t, blob.prefetchEligible())

	got := new(dns.Msg)
	require.NoError(t, got.Unpack(blob.message()))
	require.Equal(t, mustPack(t, msg), mustPack(t, got))
}

// A key with no ECS option is the common case and has an empty Net.
func TestBlobRoundTripWithoutECS(t *testing.T) {
	key := lruKey{Question: dns.Question{Name: "plain.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg := new(dns.Msg)
	msg.SetQuestion("plain.example.com.", dns.TypeA)

	blob, err := newCacheBlob(key, &cacheAnswer{Msg: msg})
	require.NoError(t, err)
	require.Equal(t, key, blob.key())
	require.True(t, blob.matchesKey(key))
}

// A question name arrives in presentation form, where every unprintable octet
// escapes to \DDD. A single 63-octet binary label is perfectly legal on the
// wire and lands well past 255 characters, so the length fields have to hold
// more than a byte. Getting this wrong doesn't corrupt anything: it makes the
// entry uncacheable and logs a warning on every query for it, which any client
// can trigger at will.
func TestBlobLongPresentationName(t *testing.T) {
	name := strings.Repeat(`\001`, 63) + ".com."
	require.Greater(t, len(name), 255, "the presentation form must exceed a uint8")

	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	a := new(dns.Msg)
	a.SetReply(q)
	rr, err := dns.NewRR(name + " 300 IN A 192.0.2.1")
	require.NoError(t, err)
	a.Answer = []dns.RR{rr}

	// It has to survive the wire, which is the whole point: the name is legal.
	wire, err := a.Pack()
	require.NoError(t, err)
	require.Less(t, len(wire), 255, "the wire form is well within the protocol limit")

	b := NewMemoryBackend(MemoryBackendOptions{GCPeriod: time.Hour})
	defer b.Close()
	now := time.Now()
	b.Store(q, &cacheAnswer{Msg: a, Timestamp: now, Expiry: now.Add(time.Hour)})

	got, _, ok := b.Lookup(q)
	require.True(t, ok, "a name this long must still cache")
	require.Equal(t, name, got.Question[0].Name)
	require.Len(t, got.Answer, 1)
}

// The length fields still have a ceiling, so the encoding stays total rather
// than silently truncating into a key that collides with another name.
func TestBlobRejectsOversizedName(t *testing.T) {
	key := lruKey{
		Question: dns.Question{Name: strings.Repeat("a", math.MaxUint16+1), Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	msg := new(dns.Msg)
	msg.SetQuestion("short.example.com.", dns.TypeA)

	_, err := newCacheBlob(key, &cacheAnswer{Msg: msg})
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

// The layout keeps everything the key is built from in one span, so a stored
// blob can be matched or hashed without decoding it back into an lruKey. That
// only holds while no volatile field sits inside the region, so pin it: two
// entries under the same key must have identical key regions however much
// their metadata and messages differ.
func TestBlobKeyRegionDependsOnlyOnTheKey(t *testing.T) {
	key := blobTestKey()
	ts := time.Date(2026, 8, 15, 9, 30, 0, 0, time.UTC)

	first, err := newCacheBlob(key, &cacheAnswer{
		Timestamp: ts, Expiry: ts.Add(time.Hour), PrefetchEligible: true, Msg: blobTestAnswer(t),
	})
	require.NoError(t, err)

	other := blobTestAnswer(t)
	rr, err := dns.NewRR("a.example.com. 60 IN A 198.51.100.9")
	require.NoError(t, err)
	other.Answer = append(other.Answer, rr)
	other.Id = 9
	second, err := newCacheBlob(key, &cacheAnswer{
		Timestamp: ts.Add(time.Minute), Expiry: ts.Add(2 * time.Hour), PrefetchEligible: false, Msg: other,
	})
	require.NoError(t, err)

	require.NotEqual(t, first.message(), second.message(), "the messages must actually differ")
	require.Equal(t, first.keyRegion(), second.keyRegion())

	// And a different key has to change it.
	otherKey := blobTestKey()
	otherKey.Question.Name = "z.example.com."
	third, err := newCacheBlob(otherKey, &cacheAnswer{Msg: blobTestAnswer(t)})
	require.NoError(t, err)
	require.NotEqual(t, first.keyRegion(), third.keyRegion())
}

// The version byte is written, not left at whatever the allocation carried.
// A blob now travels on its own into Redis and into the cache file, where the
// byte is what tells a reader the layout matches its accessors, so a blob that
// went out carrying an implicit 0 would be indistinguishable from a record
// written before the backends shared a layout.
func TestBlobVersionIsWritten(t *testing.T) {
	blob, err := newCacheBlob(blobTestKey(), &cacheAnswer{Msg: blobTestAnswer(t)})
	require.NoError(t, err)
	require.Equal(t, byte(blobVersion), blob.version())
	require.NotZero(t, blobVersion, "must be written, so it cannot be the zero value")
	require.NotEqual(t, byte(binaryFormatVersion), blob.version(),
		"must not collide with the pre-unification Redis record format")
}
