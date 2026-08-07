package rdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// For tests that don't assert on log output. Avoids mutating the global Log,
// which background goroutines from other tests read without synchronisation.
var discardLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// answerWithExpiry builds a cache answer for a name, expiring at the given time.
func answerWithExpiry(name string, expiry time.Time) *cacheAnswer {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IP{192, 0, 2, 1},
		},
	}
	return &cacheAnswer{
		Timestamp: time.Now(),
		Expiry:    expiry,
		Msg:       msg,
	}
}

func queryFor(name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	return q
}

// The hand-rolled append encoder in serialize() must produce exactly what
// encoding/json produces for the same item, so that cache files stay
// readable across versions in both directions.
func TestLRUSerializeMatchesEncodingJSON(t *testing.T) {
	future := time.Now().Add(time.Hour)

	keys := []lruKey{
		{Question: dns.Question{Name: "plain.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		// Every non-zero key field set, including ECS and the DNSSEC/CD bits.
		{
			Question: dns.Question{Name: "full.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			Net:      "192.0.2.0",
			Do:       true,
			CD:       true,
			ECSMask:  24,
		},
		// Names needing JSON escaping, exercising the fallback path.
		{Question: dns.Question{Name: `quote\".example.com.`, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		{Question: dns.Question{Name: "unicode-é中.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		{Question: dns.Question{Name: "control\x01.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		// encoding/json escapes < > & by default; these are valid label bytes.
		{Question: dns.Question{Name: "html<>&.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		// Same, but in the Net field rather than the name.
		{
			Question: dns.Question{Name: "ecs.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			Net:      "<&>",
		},
	}

	for _, key := range keys {
		t.Run(key.Question.Name, func(t *testing.T) {
			answer := answerWithExpiry(key.Question.Name, future)
			answer.PrefetchEligible = true
			item := &cacheItem{Key: key, Answer: answer}

			// What encoding/json would have produced (the previous encoder).
			var want bytes.Buffer
			require.NoError(t, json.NewEncoder(&want).Encode(item))

			// What the append encoder produces.
			c := newLRUCache(0)
			c.addKey(key, answer)
			var got bytes.Buffer
			_, err := c.serialize(&got, discardLog)
			require.NoError(t, err)

			require.Equal(t, want.String(), got.String(),
				"append encoder output must be byte-identical to encoding/json")
		})
	}
}

// A file written by serialize() must load back through deserialize() with
// keys and messages intact.
func TestLRUSerializeRoundTrip(t *testing.T) {
	future := time.Now().Add(time.Hour)
	c := newLRUCache(0)

	keys := []lruKey{
		{Question: dns.Question{Name: "a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		{
			Question: dns.Question{Name: "b.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			Net:      "192.0.2.0",
			Do:       true,
			CD:       true,
			ECSMask:  24,
		},
	}
	for _, k := range keys {
		c.addKey(k, answerWithExpiry(k.Question.Name, future))
	}

	var buf bytes.Buffer
	_, err := c.serialize(&buf, discardLog)
	require.NoError(t, err)

	loaded := newLRUCache(0)
	require.NoError(t, loaded.deserialize(&buf))
	require.Equal(t, 2, loaded.size())

	for _, k := range keys {
		item := loaded.items[k]
		require.NotNil(t, item, "key %v missing after round-trip", k)
		require.Equal(t, k.Question.Name, item.Answer.Msg.Question[0].Name)
		require.Len(t, item.Answer.Msg.Answer, 1)
		// Timestamps survive the RFC3339Nano round-trip.
		require.True(t, item.Answer.Expiry.Equal(future))
	}
}

// LRU order must survive a save/load cycle: the least-recently-used item
// is written first, so that re-inserting in file order rebuilds the same
// ordering and the right items are evicted under capacity pressure.
func TestLRUSerializePreservesLRUOrder(t *testing.T) {
	future := time.Now().Add(time.Hour)
	c := newLRUCache(0)

	names := []string{"first.example.com.", "second.example.com.", "third.example.com."}
	for _, n := range names {
		c.add(queryFor(n), answerWithExpiry(n, future))
	}
	// Touch the oldest so it becomes the most recently used.
	require.NotNil(t, c.get(queryFor("first.example.com.")))

	var buf bytes.Buffer
	_, err := c.serialize(&buf, discardLog)
	require.NoError(t, err)

	// Expected LRU order, least-recent first.
	wantOrder := []string{"second.example.com.", "third.example.com.", "first.example.com."}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, len(wantOrder))
	for i, want := range wantOrder {
		require.Contains(t, lines[i], want, "line %d should hold %s", i, want)
	}

	// Load into a cache that can only hold 2; the two most recently used win.
	loaded := newLRUCache(2)
	require.NoError(t, loaded.deserialize(&buf))
	require.Equal(t, 2, loaded.size())
	require.Nil(t, loaded.get(queryFor("second.example.com.")), "LRU item should have been evicted")
	require.NotNil(t, loaded.get(queryFor("third.example.com.")))
	require.NotNil(t, loaded.get(queryFor("first.example.com.")))
}

// Expired records shouldn't be written to the cache file.
func TestLRUSerializeSkipsExpired(t *testing.T) {
	c := newLRUCache(0)
	c.add(queryFor("live.example.com."), answerWithExpiry("live.example.com.", time.Now().Add(time.Hour)))
	c.add(queryFor("dead.example.com."), answerWithExpiry("dead.example.com.", time.Now().Add(-time.Hour)))

	var buf bytes.Buffer
	_, err := c.serialize(&buf, discardLog)
	require.NoError(t, err)

	require.Contains(t, buf.String(), "live.example.com.")
	require.NotContains(t, buf.String(), "dead.example.com.")
	require.Equal(t, 1, strings.Count(buf.String(), "\n"))
}

// Records that expired while the file sat on disk must not be loaded back
// into the cache, where they would hold capacity until the next GC run.
func TestLRUDeserializeSkipsExpired(t *testing.T) {
	// Build a file directly via encoding/json so the expired record is
	// present regardless of what serialize() filters out.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, tc := range []struct {
		name   string
		expiry time.Time
	}{
		{"dead.example.com.", time.Now().Add(-time.Hour)},
		{"live.example.com.", time.Now().Add(time.Hour)},
	} {
		key := lruKey{Question: dns.Question{Name: tc.name, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		require.NoError(t, enc.Encode(&cacheItem{Key: key, Answer: answerWithExpiry(tc.name, tc.expiry)}))
	}

	c := newLRUCache(0)
	require.NoError(t, c.deserialize(&buf))

	require.Equal(t, 1, c.size())
	require.NotNil(t, c.get(queryFor("live.example.com.")))
	require.Nil(t, c.get(queryFor("dead.example.com.")))
}

// A cache file written by the previous encoding/json-based encoder must
// still load, since upgrading must not discard an existing cache.
func TestLRUDeserializeOldFormat(t *testing.T) {
	future := time.Now().Add(time.Hour)
	key := lruKey{
		Question: dns.Question{Name: "old.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Net:      "192.0.2.0",
		Do:       true,
		ECSMask:  24,
	}

	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(&cacheItem{
		Key:    key,
		Answer: answerWithExpiry("old.example.com.", future),
	}))

	c := newLRUCache(0)
	require.NoError(t, c.deserialize(&buf))
	require.Equal(t, 1, c.size())
	require.NotNil(t, c.items[key])
}

// An answer whose message can't be packed: the owner name is too long to be
// a valid, escapable FQDN.
func unpackableAnswer(name string, expiry time.Time) *cacheAnswer {
	a := answerWithExpiry(name, expiry)
	a.Msg.Answer[0].Header().Name = strings.Repeat("a", 300)
	return a
}

// An unpackable message must be skipped rather than failing the whole save.
func TestLRUSerializeSkipsUnpackableMessage(t *testing.T) {
	future := time.Now().Add(time.Hour)
	c := newLRUCache(0)

	c.add(queryFor("good.example.com."), answerWithExpiry("good.example.com.", future))
	c.add(queryFor("bad.example.com."), unpackableAnswer("bad.example.com.", future))

	var buf bytes.Buffer
	skipped, err := c.serialize(&buf, discardLog)
	require.NoError(t, err, "one bad record must not fail the save")
	require.Equal(t, 1, skipped, "the dropped record must be reported to the caller")
	require.Contains(t, buf.String(), "good.example.com.")
	require.Equal(t, 1, strings.Count(buf.String(), "\n"))
}

// Unpackable records are reported once with a count, not once per record, so
// that a systematic failure doesn't flood the log on every save-interval.
//
// The logger is passed in rather than swapping the package-global Log: that
// global is read without synchronisation by background goroutines other tests
// leave running, so mutating it here races (and did, under -race).
func TestLRUSerializeSkipsAreLoggedOnce(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	future := time.Now().Add(time.Hour)
	c := newLRUCache(0)
	c.add(queryFor("good.example.com."), answerWithExpiry("good.example.com.", future))
	for _, n := range []string{"bad1.example.com.", "bad2.example.com.", "bad3.example.com."} {
		c.add(queryFor(n), unpackableAnswer(n, future))
	}

	var buf bytes.Buffer
	skipped, err := c.serialize(&buf, log)
	require.NoError(t, err)
	require.Equal(t, 3, skipped)

	require.Equal(t, 1, strings.Count(logs.String(), "not persisted"),
		"expected a single summary line, got:\n%s", logs.String())
	require.Contains(t, logs.String(), "skipped=3")
	// The good record is still written.
	require.Equal(t, 1, strings.Count(buf.String(), "\n"))
}

// live() is the shared expiry rule for lookups, GC, and both sides of
// persistence, so pin its boundary: a record is live up to and including
// its expiry instant.
func TestCacheAnswerLive(t *testing.T) {
	now := time.Now()
	a := &cacheAnswer{Expiry: now}

	require.True(t, a.live(now.Add(-time.Nanosecond)))
	require.True(t, a.live(now), "a record is live at exactly its expiry")
	require.False(t, a.live(now.Add(time.Nanosecond)))
}

// The skip count must reach the expvar, not just the return value.
func TestMemoryBackendSaveSkippedMetric(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cache.db")
	future := time.Now().Add(time.Hour)

	b := &memoryBackend{
		lru:         newLRUCache(0),
		saveSkipped: getVarInt("cache", "memory-test", "save-skipped"),
	}
	b.lru.add(queryFor("good.example.com."), answerWithExpiry("good.example.com.", future))
	b.lru.add(queryFor("bad.example.com."), unpackableAnswer("bad.example.com.", future))

	// expvars are process-global, so compare against the starting value.
	before := b.saveSkipped.Value()
	require.NoError(t, b.writeToFile(filename))
	require.Equal(t, before+1, b.saveSkipped.Value(),
		"the dropped record should be counted in the expvar")
}

// Exercises the actual file path, including the buffered writer and its
// flush, which the in-memory serialize tests bypass.
func TestMemoryBackendFileRoundTrip(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cache.db")
	future := time.Now().Add(time.Hour)

	b := &memoryBackend{lru: newLRUCache(0)}
	for _, n := range []string{"a.example.com.", "b.example.com."} {
		b.lru.add(queryFor(n), answerWithExpiry(n, future))
	}
	// An expired record must not make it into the file.
	b.lru.add(queryFor("gone.example.com."),
		answerWithExpiry("gone.example.com.", time.Now().Add(-time.Hour)))

	require.NoError(t, b.writeToFile(filename))

	loaded := &memoryBackend{lru: newLRUCache(0)}
	require.NoError(t, loaded.loadFromFile(filename))
	require.Equal(t, 2, loaded.Size())

	answer, _, ok := loaded.Lookup(queryFor("a.example.com."))
	require.True(t, ok, "record should be served from the reloaded cache")
	require.Equal(t, "a.example.com.", answer.Answer[0].Header().Name)
}

// A periodic SaveInterval write can overlap the one from Close(). However
// they interleave, the cache file must always be a complete save rather than
// a mix of two, and no temp files may be left behind.
//
// Note this passes with saveMu removed: writing to a uniquely-named temp file
// and renaming into place is what makes the result atomic. saveMu is kept to
// avoid redundant concurrent encodes, not for file integrity. What this test
// does catch is a regression to writing (and truncating) the target file
// directly, which corrupts it under concurrent saves.
func TestMemoryBackendConcurrentSaves(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cache.db")
	future := time.Now().Add(time.Hour)

	b := &memoryBackend{lru: newLRUCache(0)}
	for i := range 500 {
		n := fmt.Sprintf("host%d.example.com.", i)
		b.lru.add(queryFor(n), answerWithExpiry(n, future))
	}

	// Hammer the same file from several goroutines while the cache shrinks,
	// so the writes are of differing lengths. Errors are collected rather
	// than asserted here; require/FailNow is only legal on the test goroutine.
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				if err := b.writeToFile(filename); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		}()
	}
	for i := range 400 {
		b.mu.Lock()
		b.lru.delete(queryFor(fmt.Sprintf("host%d.example.com.", i)))
		b.mu.Unlock()
	}
	wg.Wait()
	require.Empty(t, errs, "concurrent saves should all succeed")

	// Whatever the interleaving, the resulting file must be a complete,
	// parseable cache rather than a mix of two different saves.
	f, err := os.Open(filename)
	require.NoError(t, err)
	defer f.Close()
	loaded := newLRUCache(0)
	require.NoError(t, loaded.deserialize(f), "cache file must not be corrupt")

	requireOnlyFile(t, filename)
}

func BenchmarkLRUSerialize(b *testing.B) {
	future := time.Now().Add(time.Hour)
	c := newLRUCache(0)
	for i := range 1000 {
		name := fmt.Sprintf("host%d.example.com.", i)
		c.add(queryFor(name), answerWithExpiry(name, future))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var buf bytes.Buffer
		if _, err := c.serialize(&buf, discardLog); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLRUDeserialize(b *testing.B) {
	future := time.Now().Add(time.Hour)
	c := newLRUCache(0)
	for i := range 1000 {
		name := fmt.Sprintf("host%d.example.com.", i)
		c.add(queryFor(name), answerWithExpiry(name, future))
	}
	var buf bytes.Buffer
	if _, err := c.serialize(&buf, discardLog); err != nil {
		b.Fatal(err)
	}
	data := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if err := newLRUCache(0).deserialize(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
