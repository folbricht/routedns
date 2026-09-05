package rdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func rawTestEntry(t *testing.T, i int) (*dns.Msg, *cacheAnswer) {
	t.Helper()
	name := fmt.Sprintf("host%d.example.com.", i)
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	a := new(dns.Msg)
	a.SetReply(q)
	rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN A 192.0.%d.%d", name, i/256, i%256))
	require.NoError(t, err)
	a.Answer = []dns.RR{rr}

	now := time.Now()
	return q, &cacheAnswer{Msg: a, Timestamp: now, Expiry: now.Add(time.Hour)}
}

func fillCache(t *testing.T, c *lruCache, n int) []*dns.Msg {
	t.Helper()
	queries := make([]*dns.Msg, n)
	for i := range n {
		q, answer := rawTestEntry(t, i)
		queries[i] = q
		key := lruKeyFromQuery(q)
		blob, err := newCacheBlob(key, answer)
		require.NoError(t, err)
		c.addKey(key, blob)
	}
	return queries
}

func TestRawCacheFileRoundTrip(t *testing.T) {
	src := newLRUCache(0)
	queries := fillCache(t, src, 20)

	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))

	dst := newLRUCache(0)
	require.NoError(t, dst.deserializeRaw(bytes.NewReader(buf.Bytes())))
	require.Equal(t, len(queries), dst.size())
	for _, q := range queries {
		key := lruKeyFromQuery(q)
		require.NotNil(t, dst.find(dst.hash(key), key), "%s must be findable again", key.Question.Name)
	}

	// Writing it back out reproduces the file, so the queue order survives too
	// and the least recently used entry is still the first to go.
	var again bytes.Buffer
	require.NoError(t, dst.serializeRaw(&again))
	require.Equal(t, buf.Bytes(), again.Bytes())
}

// The option picks the format to write; the format to read comes from the file
// itself, so an existing cache survives the option being changed either way.
func TestCacheFileFormatIsDetectedNotConfigured(t *testing.T) {
	for _, tc := range []struct {
		wrote, prefix, thenRunsAs string
	}{
		{"", "{", CacheFileFormatRaw},                            // unset writes JSON
		{CacheFileFormatRaw, rawCacheMagic, CacheFileFormatJSON}, // raw read back by a JSON-configured run
	} {
		t.Run(tc.wrote+"-then-"+tc.thenRunsAs, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "cache")

			first := NewMemoryBackend(MemoryBackendOptions{
				GCPeriod: time.Hour, Filename: filename, FileFormat: tc.wrote,
			})
			queries := make([]*dns.Msg, 5)
			for i := range queries {
				q, answer := rawTestEntry(t, i)
				queries[i] = q
				first.Store(q, answer)
			}
			require.NoError(t, first.Close())

			content, err := os.ReadFile(filename)
			require.NoError(t, err)
			require.True(t, bytes.HasPrefix(content, []byte(tc.prefix)), "%q wrote the wrong format", tc.wrote)

			second := NewMemoryBackend(MemoryBackendOptions{
				GCPeriod: time.Hour, Filename: filename, FileFormat: tc.thenRunsAs,
			})
			defer second.Close()
			require.Equal(t, len(queries), second.Size())
			for _, q := range queries {
				_, _, ok := second.Lookup(q)
				require.True(t, ok, "%s must survive the format switch", q.Question[0].Name)
			}
		})
	}
}

// Downgrading the binary has to cost a cold cache and nothing worse, which is
// what the magic buys: a build that predates the format can't parse it.
func TestRawCacheFileRejectedByJSONReader(t *testing.T) {
	src := newLRUCache(0)
	fillCache(t, src, 3)
	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))

	dst := newLRUCache(0)
	require.Error(t, dst.deserialize(bytes.NewReader(buf.Bytes())))
	require.Zero(t, dst.size())
}

// Damage to a record costs that record; damage to the framing costs the rest
// of the file, because there is no way to find the next record from it. Either
// way what was read before it is kept.
func TestRawCacheFileCorruption(t *testing.T) {
	src := newLRUCache(0)
	fillCache(t, src, 10)
	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))
	good := buf.Bytes()
	firstLen := int(binary.BigEndian.Uint32(good[rawCacheHeaderLen:]))

	t.Run("corrupt message skips one record", func(t *testing.T) {
		// Scribble on the packed message, leaving the framing intact.
		damaged := bytes.Clone(good)
		msg := damaged[rawCacheHeaderLen+4 : rawCacheHeaderLen+4+firstLen]
		for i := len(msg) - 8; i < len(msg); i++ {
			msg[i] = 0xff
		}
		dst := newLRUCache(0)
		require.NoError(t, dst.deserializeRaw(bytes.NewReader(damaged)))
		require.Equal(t, 9, dst.size(), "the other records still load")
	})

	t.Run("truncated file keeps what came before", func(t *testing.T) {
		dst := newLRUCache(0)
		require.NoError(t, dst.deserializeRaw(bytes.NewReader(good[:len(good)-20])))
		require.Equal(t, 9, dst.size())
	})

	t.Run("implausible length is refused not allocated", func(t *testing.T) {
		damaged := bytes.Clone(good)
		binary.BigEndian.PutUint32(damaged[rawCacheHeaderLen+4+firstLen:], 3_000_000_000)
		dst := newLRUCache(0)
		require.NoError(t, dst.deserializeRaw(bytes.NewReader(damaged)))
		require.Equal(t, 1, dst.size(), "only the record before the bad length is kept")
	})
}

// A stored entry is not bounded by the 64KB wire limit: the cache packs
// without name compression, so a response that arrived comfortably inside the
// limit can be twice that once stored. The record limit has to leave room for
// it rather than dropping the largest entries on the way to disk.
func TestRawCacheFileKeepsOversizedEntries(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("big.example.com.", dns.TypeTXT)
	a := new(dns.Msg)
	a.SetReply(q)
	name := strings.Repeat("averylonglabelusedtomakethisnamebig.", 6) + "example.com."
	for range 290 {
		rr, err := dns.NewRR(fmt.Sprintf(`%s 3600 IN TXT "%s"`, name, strings.Repeat("x", 200)))
		require.NoError(t, err)
		a.Answer = append(a.Answer, rr)
	}

	a.Compress = true
	onTheWire, err := a.Pack()
	require.NoError(t, err)
	require.Less(t, len(onTheWire), dns.MaxMsgSize, "this has to be a response that could arrive")
	a.Compress = false

	now := time.Now()
	key := lruKeyFromQuery(q)
	blob, err := newCacheBlob(key, &cacheAnswer{Msg: a, Timestamp: now, Expiry: now.Add(time.Hour)})
	require.NoError(t, err)
	require.Greater(t, len(blob), dns.MaxMsgSize, "stored uncompressed, it outgrows the wire limit")

	src := newLRUCache(0)
	src.addKey(key, blob)
	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))

	dst := newLRUCache(0)
	require.NoError(t, dst.deserializeRaw(bytes.NewReader(buf.Bytes())))
	require.Equal(t, 1, dst.size(), "the entry must survive the file, not be skipped")
}

// Persisting blobs makes their version byte part of an on-disk format, so a
// record laid out by a later version has to be refused rather than read
// through accessors that no longer match it.
func TestRawCacheFileRejectsUnknownBlobVersion(t *testing.T) {
	src := newLRUCache(0)
	fillCache(t, src, 3)
	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))

	damaged := bytes.Clone(buf.Bytes())
	damaged[rawCacheHeaderLen+4+blobOffVersion] = blobVersion + 1

	dst := newLRUCache(0)
	require.NoError(t, dst.deserializeRaw(bytes.NewReader(damaged)))
	require.Equal(t, 2, dst.size(), "the record with an unknown layout is skipped, the rest load")
}

// A raw file holds blobs, so its version has to move whenever blobVersion
// does. If it doesn't, the header check passes and every record is then
// rejected one at a time by the per-record version check, which is the silent
// empty cache the header check exists to prevent. Nothing in the types ties
// the two constants together, so pin both: changing either should mean coming
// here and deciding about the other.
func TestRawCacheFileVersionTracksBlobVersion(t *testing.T) {
	require.Equal(t, 2, rawCacheVersion, "if this moved, blobVersion likely has to move with it")
	require.Equal(t, 2, blobVersion, "if this moved, rawCacheVersion has to move with it")
}

// A file written before the backends shared a record layout is refused at the
// header, so it reports a cold start rather than being accepted and then
// losing every record to the per-record check without a word.
func TestRawCacheFileRejectsOlderFileVersion(t *testing.T) {
	src := newLRUCache(0)
	fillCache(t, src, 3)
	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))

	older := bytes.Clone(buf.Bytes())
	older[len(rawCacheMagic)] = rawCacheVersion - 1

	dst := newLRUCache(0)
	err := dst.deserializeRaw(bytes.NewReader(older))
	require.Error(t, err, "an older file version must be refused, not read")
	require.Contains(t, err.Error(), "unsupported raw cache file version")
	require.Zero(t, dst.size())
}
