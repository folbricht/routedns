package rdns

import (
	"fmt"
	"net"
	"sync"
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

func TestEncodeDecode(t *testing.T) {
	// Create a test DNS message
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess

	// Add an answer
	rr, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	require.NoError(t, err)
	msg.Answer = append(msg.Answer, rr)

	// Create a cacheAnswer
	now := time.Now()
	original := &cacheAnswer{
		Timestamp:        now,
		PrefetchEligible: true,
		Msg:              msg,
	}

	// Encode
	encoded, err := encodeCacheAnswer(nil, original)
	require.NoError(t, err)

	// Verify format
	require.GreaterOrEqual(t, len(encoded), headerSize, "encoded data too short")

	// Check version byte
	require.Equal(t, byte(binaryFormatVersion), encoded[0], "version byte")

	// Check flags byte
	expectedFlags := byte(flagPrefetchBit)
	require.Equal(t, expectedFlags, encoded[1], "flags byte")

	// Decode
	decoded, err := decodeCacheAnswer(encoded)
	require.NoError(t, err)

	// Verify fields
	require.Equal(t, original.Timestamp.Unix(), decoded.Timestamp.Unix())
	require.Equal(t, original.PrefetchEligible, decoded.PrefetchEligible)

	// Verify DNS message
	require.Len(t, decoded.Msg.Answer, len(original.Msg.Answer))
	require.Equal(t, original.Msg.Question[0].Name, decoded.Msg.Question[0].Name)
	require.Equal(t, original.Msg.Question[0].Qtype, decoded.Msg.Question[0].Qtype)
}

func TestEncodeDecodeNoPrefetch(t *testing.T) {
	// Create a test DNS message
	msg := new(dns.Msg)
	msg.SetQuestion("test.example.", dns.TypeAAAA)
	msg.Response = true

	// Create a cacheAnswer with prefetch disabled
	original := &cacheAnswer{
		Timestamp:        time.Unix(1234567890, 0),
		PrefetchEligible: false,
		Msg:              msg,
	}

	// Encode
	encoded, err := encodeCacheAnswer(nil, original)
	require.NoError(t, err)

	// Check flags byte (should be 0)
	require.Equal(t, byte(0), encoded[1], "flags byte")

	// Decode
	decoded, err := decodeCacheAnswer(encoded)
	require.NoError(t, err)

	require.False(t, decoded.PrefetchEligible)
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

func TestEncodeAliasesBuffer(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("alias.test.", dns.TypeA)
	msg.Response = true

	item := &cacheAnswer{
		Timestamp:        time.Unix(1234567890, 0),
		PrefetchEligible: true,
		Msg:              msg,
	}

	// A buffer with enough capacity is used for the result
	buf := make([]byte, 0, 2048)
	encoded, err := encodeCacheAnswer(buf, item)
	require.NoError(t, err)
	require.Same(t, &buf[:1][0], &encoded[0], "expected result to alias the provided buffer")

	// A buffer that's too small for the message is not used; the result
	// must still be complete and decode correctly
	small := make([]byte, 0, headerSize+4)
	encodedSmall, err := encodeCacheAnswer(small, item)
	require.NoError(t, err)
	require.NotSame(t, &small[:1][0], &encodedSmall[0], "expected result not to alias the undersized buffer")
	require.Equal(t, encoded, encodedSmall)

	decoded, err := decodeCacheAnswer(encodedSmall)
	require.NoError(t, err)
	require.Equal(t, "alias.test.", decoded.Msg.Question[0].Name)

	// A nil buffer works too
	encodedNil, err := encodeCacheAnswer(nil, item)
	require.NoError(t, err)
	require.Equal(t, encoded, encodedNil)
}

func TestEncodeBufferReuse(t *testing.T) {
	// Encode repeatedly into the same buffer, the way Store does with
	// pooled buffers, and verify each result round-trips
	msg := new(dns.Msg)
	msg.SetQuestion("pool.test.", dns.TypeA)
	msg.Response = true

	item := &cacheAnswer{
		Timestamp:        time.Now(),
		PrefetchEligible: true,
		Msg:              msg,
	}

	buf := make([]byte, 0, 2048)
	for i := range 100 {
		encoded, err := encodeCacheAnswer(buf, item)
		require.NoError(t, err, "iteration %d", i)

		// Verify first byte is always version
		require.Equal(t, byte(binaryFormatVersion), encoded[0], "iteration %d: version byte", i)

		// Decode to verify correctness
		decoded, err := decodeCacheAnswer(encoded)
		require.NoError(t, err, "iteration %d", i)

		require.Equal(t, "pool.test.", decoded.Msg.Question[0].Name, "iteration %d: corrupted data", i)
	}
}

func TestEncodeConcurrent(t *testing.T) {
	// Test concurrent encoding, each goroutine reusing its own buffer.
	// Each goroutine gets its own dns.Msg to avoid racing on shared message internals
	const numGoroutines = 50
	const numIterations = 100

	errs := make(chan error, numGoroutines)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := range numGoroutines {
		go func(gid int) {
			defer wg.Done()

			msg := new(dns.Msg)
			msg.SetQuestion("concurrent.test.", dns.TypeA)
			msg.Response = true
			rr, err := dns.NewRR("concurrent.test. 300 IN A 192.0.2.1")
			if err != nil {
				errs <- err
				return
			}
			msg.Answer = append(msg.Answer, rr)

			item := &cacheAnswer{
				Timestamp:        time.Now(),
				PrefetchEligible: true,
				Msg:              msg,
			}

			buf := make([]byte, 0, 2048)
			for i := range numIterations {
				encoded, err := encodeCacheAnswer(buf, item)
				if err != nil {
					errs <- err
					return
				}
				if encoded[0] != binaryFormatVersion {
					errs <- fmt.Errorf("goroutine %d iteration %d: invalid version byte %d", gid, i, encoded[0])
					return
				}
				decoded, err := decodeCacheAnswer(encoded)
				if err != nil {
					errs <- err
					return
				}
				if decoded.Msg.Question[0].Name != "concurrent.test." {
					errs <- fmt.Errorf("goroutine %d iteration %d: corrupted data, got name %s", gid, i, decoded.Msg.Question[0].Name)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err, "concurrent encode/decode failed")
	}
}

func BenchmarkEncodeCacheAnswer(b *testing.B) {
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

	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := encodeCacheAnswer(buf, item); err != nil {
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
