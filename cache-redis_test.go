package rdns

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The Redis cache key must distinguish CD=0 from CD=1 (RFC 4035 §4.7 /
// RFC 6840 §5.9) and ECS responses with a different source-prefix length.
func TestRedisKeyFromQuery(t *testing.T) {
	b := &redisBackend{}

	queryCD := func(cd bool) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		q.CheckingDisabled = cd
		return q
	}
	require.NotEqual(t, b.keyFromQuery(queryCD(false)), b.keyFromQuery(queryCD(true)), "CD=0 and CD=1 queries produced the same Redis cache key")

	queryECS := func(mask uint8) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		q.SetEdns0(4096, false)
		ecs := new(dns.EDNS0_SUBNET)
		ecs.Code = dns.EDNS0SUBNET
		ecs.Family = 1
		ecs.SourceNetmask = mask
		ecs.Address = net.IP{192, 0, 2, 0}
		q.IsEdns0().Option = append(q.IsEdns0().Option, ecs)
		return q
	}
	require.NotEqual(t, b.keyFromQuery(queryECS(24)), b.keyFromQuery(queryECS(16)), "ECS queries with different source-prefix lengths produced the same Redis cache key")

	// The key format must remain stable so existing cache entries stay
	// valid across upgrades.
	require.Equal(t, "prefix:example.com.:IN:A::", (&redisBackend{opt: RedisBackendOptions{KeyPrefix: "prefix:"}}).keyFromQuery(queryCD(false)))
	require.Equal(t, "example.com.:IN:A::false:192.0.2.0/24", b.keyFromQuery(queryECS(24)))
}

func TestDecodeInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x01, 0x00}},
		{"wrong version", []byte{0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"invalid DNS", []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeCacheAnswer(tt.data)
			require.Error(t, err)
		})
	}
}

func BenchmarkEncodeCacheRecord(b *testing.B) {
	msg := new(dns.Msg)
	msg.SetQuestion("bench.example.com.", dns.TypeA)
	msg.Response = true
	for i := range 4 {
		rr, err := dns.NewRR(fmt.Sprintf("bench.example.com. 300 IN A 192.0.2.%d", i+1))
		require.NoError(b, err)
		msg.Answer = append(msg.Answer, rr)
	}

	item := &cacheAnswer{
		Timestamp:        time.Now(),
		PrefetchEligible: true,
		Msg:              msg,
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := newCacheBlob(lruKey{}, item); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyFromQuery(b *testing.B) {
	backend := &redisBackend{opt: RedisBackendOptions{KeyPrefix: "routedns:"}}
	q := new(dns.Msg)
	q.SetQuestion("bench.example.com.", dns.TypeA)
	q.SetEdns0(4096, true)

	b.ReportAllocs()
	for b.Loop() {
		_ = backend.keyFromQuery(q)
	}
}

// The reader ships a release ahead of the writer, so the version 2 path has to
// work before anything in this backend produces one. Build the record the way
// the memory backend does and read it back through the dispatch.
func TestRedisReadsVersion2Records(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("shared.example.", dns.TypeA)
	msg.Response = true
	rr, err := dns.NewRR("shared.example. 300 IN A 192.0.2.9")
	require.NoError(t, err)
	msg.Answer = append(msg.Answer, rr)

	now := time.Now()
	for _, eligible := range []bool{false, true} {
		// The empty key is what the writer will store: the redis key already
		// encodes the question, so the record does not repeat it.
		encoded, err := newCacheBlob(lruKey{}, &cacheAnswer{
			Timestamp:        now,
			Expiry:           now.Add(5 * time.Minute),
			PrefetchEligible: eligible,
			Msg:              msg,
		})
		require.NoError(t, err)
		require.Equal(t, byte(blobVersion), encoded.version())

		decoded, err := decodeRecord(encoded)
		require.NoError(t, err)
		require.Equal(t, eligible, decoded.PrefetchEligible)
		require.Equal(t, now.UnixNano(), decoded.Timestamp.UnixNano())
		require.Equal(t, "shared.example.", decoded.Msg.Question[0].Name)
	}
}

// Records this backend writes today keep being read, which is the direction
// that matters while a version 1 writer is still running somewhere.
func TestRedisReadsVersion1Records(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("legacy.example.", dns.TypeA)
	msg.Response = true

	encoded := encodeVersion1(t, &cacheAnswer{
		Timestamp:        time.Unix(1234567890, 0),
		PrefetchEligible: true,
		Msg:              msg,
	})
	require.Equal(t, byte(binaryFormatVersion), encoded[0])

	decoded, err := decodeRecord(encoded)
	require.NoError(t, err)
	require.True(t, decoded.PrefetchEligible)
	require.Equal(t, "legacy.example.", decoded.Msg.Question[0].Name)
}

// encodeVersion1 writes the format this backend used before it shared a layout
// with the memory backend. The production encoder is gone, so the compatibility
// path needs a fixture of its own; this goes when reading version 1 does.
func encodeVersion1(t *testing.T, item *cacheAnswer) []byte {
	t.Helper()
	wire, err := item.Msg.Pack()
	require.NoError(t, err)
	record := make([]byte, headerSize+len(wire))
	record[0] = binaryFormatVersion
	if item.PrefetchEligible {
		record[1] = flagPrefetchBit
	}
	binary.BigEndian.PutUint64(record[2:10], uint64(item.Timestamp.Unix()))
	copy(record[headerSize:], wire)
	return record
}

func TestDecodeRecordRejectsUnknownVersion(t *testing.T) {
	_, err := decodeRecord(nil)
	require.Error(t, err, "an empty record has no version to dispatch on")

	_, err = decodeRecord([]byte{0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported cache record version")
}
