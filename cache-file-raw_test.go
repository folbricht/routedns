package rdns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
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

// A cache written in the raw format has to come back entry for entry, with the
// queue order preserved so the least recently used entry is still the first to
// go once the cache is full again.
func TestRawCacheFileRoundTrip(t *testing.T) {
	const entries = 20
	src := newLRUCache(0)
	queries := fillCache(t, src, entries)

	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))

	dst := newLRUCache(0)
	require.NoError(t, dst.deserializeRaw(bytes.NewReader(buf.Bytes())))
	require.Equal(t, entries, dst.size())

	for _, q := range queries {
		item := dst.find(dst.hash(lruKeyFromQuery(q)), lruKeyFromQuery(q))
		require.NotNil(t, item, "%s must be in the reloaded cache", q.Question[0].Name)
		require.Equal(t, q.Question[0].Name, item.blob.key().Question.Name)
	}

	// Writing the reloaded cache back out has to produce the same bytes.
	var again bytes.Buffer
	require.NoError(t, dst.serializeRaw(&again))
	require.Equal(t, buf.Bytes(), again.Bytes())
}

// The format is taken from the file, not the configuration, so an existing
// cache survives the option being switched either way.
func TestCacheFileFormatIsDetectedNotConfigured(t *testing.T) {
	for _, tc := range []struct{ wrote, thenRunsAs string }{
		{CacheFileFormatJSON, CacheFileFormatRaw},
		{CacheFileFormatRaw, CacheFileFormatJSON},
		{CacheFileFormatRaw, CacheFileFormatRaw},
		{CacheFileFormatJSON, CacheFileFormatJSON},
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

			second := NewMemoryBackend(MemoryBackendOptions{
				GCPeriod: time.Hour, Filename: filename, FileFormat: tc.thenRunsAs,
			})
			defer second.Close()
			require.Equal(t, len(queries), second.Size(), "the cache written as %s was not read back", tc.wrote)
			for _, q := range queries {
				_, _, ok := second.Lookup(q)
				require.True(t, ok, "%s must survive the format switch", q.Question[0].Name)
			}
		})
	}
}

// A file written in the raw format is not readable by a build that predates
// it. That has to degrade to an empty cache rather than anything worse, since
// downgrading the binary is a normal thing to do.
func TestRawCacheFileRejectedByJSONReader(t *testing.T) {
	src := newLRUCache(0)
	fillCache(t, src, 3)
	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))

	dst := newLRUCache(0)
	require.Error(t, dst.deserialize(bytes.NewReader(buf.Bytes())))
	require.Zero(t, dst.size())
}

// Damage to the framing costs the rest of the file, damage to one record costs
// only that record. Either way what was read before it is kept.
func TestRawCacheFileCorruption(t *testing.T) {
	src := newLRUCache(0)
	fillCache(t, src, 10)
	var buf bytes.Buffer
	require.NoError(t, src.serializeRaw(&buf))
	good := buf.Bytes()

	t.Run("truncated mid-record", func(t *testing.T) {
		dst := newLRUCache(0)
		require.NoError(t, dst.deserializeRaw(bytes.NewReader(good[:len(good)-20])))
		require.Equal(t, 9, dst.size(), "the entries before the truncation are kept")
	})

	t.Run("implausible length stops the read", func(t *testing.T) {
		// Point the second record's length prefix at something enormous. It
		// must be refused outright rather than allocating for it.
		damaged := bytes.Clone(good)
		firstLen := binary.BigEndian.Uint32(damaged[rawCacheHeaderLen:])
		at := rawCacheHeaderLen + 4 + int(firstLen)
		binary.BigEndian.PutUint32(damaged[at:], 3_000_000_000)

		dst := newLRUCache(0)
		require.NoError(t, dst.deserializeRaw(bytes.NewReader(damaged)))
		require.Equal(t, 1, dst.size(), "only the record before the bad length is kept")
	})

	t.Run("corrupt message skips one record", func(t *testing.T) {
		// Scribble over the packed message of the first record, leaving the
		// framing intact, so reading carries on past it.
		damaged := bytes.Clone(good)
		firstLen := int(binary.BigEndian.Uint32(damaged[rawCacheHeaderLen:]))
		msg := damaged[rawCacheHeaderLen+4 : rawCacheHeaderLen+4+firstLen]
		for i := len(msg) - 8; i < len(msg); i++ {
			msg[i] = 0xff
		}

		dst := newLRUCache(0)
		require.NoError(t, dst.deserializeRaw(bytes.NewReader(damaged)))
		require.Equal(t, 9, dst.size(), "the other records still load")
	})

	t.Run("header only", func(t *testing.T) {
		dst := newLRUCache(0)
		require.NoError(t, dst.deserializeRaw(bytes.NewReader(good[:rawCacheHeaderLen])))
		require.Zero(t, dst.size())
	})

	t.Run("wrong version", func(t *testing.T) {
		damaged := bytes.Clone(good)
		damaged[len(rawCacheMagic)] = rawCacheVersion + 1
		dst := newLRUCache(0)
		require.Error(t, dst.deserializeRaw(bytes.NewReader(damaged)))
	})
}

// Size and speed are the reason the format exists, so record what it actually
// achieves against the JSON format on the same cache.
func TestRawCacheFileIsSmaller(t *testing.T) {
	c := newLRUCache(0)
	fillCache(t, c, 1000)

	var raw, jsonBuf bytes.Buffer
	require.NoError(t, c.serializeRaw(&raw))
	require.NoError(t, c.serialize(&jsonBuf))

	t.Logf("1000 entries: raw %d B (%.0f B/record), json %d B (%.0f B/record)",
		raw.Len(), float64(raw.Len())/1000, jsonBuf.Len(), float64(jsonBuf.Len())/1000)
	require.Less(t, raw.Len(), jsonBuf.Len()/2, "raw should be well under half the size")
}

// The file the backend writes has to be the format that was asked for.
func TestMemoryBackendWritesRequestedFormat(t *testing.T) {
	for _, format := range []string{CacheFileFormatJSON, CacheFileFormatRaw, ""} {
		filename := filepath.Join(t.TempDir(), "cache")
		b := NewMemoryBackend(MemoryBackendOptions{
			GCPeriod: time.Hour, Filename: filename, FileFormat: format,
		})
		q, answer := rawTestEntry(t, 0)
		b.Store(q, answer)
		require.NoError(t, b.Close())

		content, err := os.ReadFile(filename)
		require.NoError(t, err)
		if format == CacheFileFormatRaw {
			require.True(t, bytes.HasPrefix(content, []byte(rawCacheMagic)))
		} else {
			require.True(t, bytes.HasPrefix(content, []byte("{")), "%q must default to JSON", format)
		}
	}
}
