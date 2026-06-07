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
	encoded, err := encodeCacheAnswer(original)
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
	encoded, err := encodeCacheAnswer(original)
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

func TestEncodeDecodePooling(t *testing.T) {
	// Test that pooling works correctly across multiple encode operations
	msg := new(dns.Msg)
	msg.SetQuestion("pool.test.", dns.TypeA)
	msg.Response = true

	item := &cacheAnswer{
		Timestamp:        time.Now(),
		PrefetchEligible: true,
		Msg:              msg,
	}

	// Encode multiple times to test pool reuse
	for i := range 100 {
		encoded, err := encodeCacheAnswer(item)
		require.NoError(t, err, "iteration %d", i)

		// Verify first byte is always version
		require.Equal(t, byte(binaryFormatVersion), encoded[0], "iteration %d: version byte", i)

		// Decode to verify correctness
		decoded, err := decodeCacheAnswer(encoded)
		require.NoError(t, err, "iteration %d", i)

		require.Equal(t, "pool.test.", decoded.Msg.Question[0].Name, "iteration %d: corrupted data", i)
	}
}

func TestEncodeReturnsIndependentSlice(t *testing.T) {
	// Verify that encoded bytes are independent of the pool and mutations don't affect subsequent encodes
	msg := new(dns.Msg)
	msg.SetQuestion("independent.test.", dns.TypeA)
	msg.Response = true

	item := &cacheAnswer{
		Timestamp:        time.Unix(1234567890, 0),
		PrefetchEligible: true,
		Msg:              msg,
	}

	// First encode
	encoded1, err := encodeCacheAnswer(item)
	require.NoError(t, err)

	// Save a copy of the original encoded data
	original := make([]byte, len(encoded1))
	copy(original, encoded1)

	// Mutate the returned slice to verify it's independent of the pool
	for i := range encoded1 {
		encoded1[i] = 0xFF
	}

	// Verify the mutated buffer is now garbage and fails to decode
	_, err = decodeCacheAnswer(encoded1)
	require.Error(t, err, "expected decode of mutated buffer to fail")

	// Second encode - should succeed and produce the same result as the first
	encoded2, err := encodeCacheAnswer(item)
	require.NoError(t, err)

	// Verify second encode matches the original (not corrupted by mutation)
	require.Equal(t, original, encoded2, "mutation leaked into pool")

	// Verify we can still decode the second result
	decoded, err := decodeCacheAnswer(encoded2)
	require.NoError(t, err)

	require.Equal(t, "independent.test.", decoded.Msg.Question[0].Name)
}

func TestEncodeConcurrent(t *testing.T) {
	// Test concurrent encoding to catch pool-related race conditions
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

			for i := range numIterations {
				encoded, err := encodeCacheAnswer(item)
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
