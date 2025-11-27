package rdns

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEncodeDecode(t *testing.T) {
	// Create a test DNS message
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess

	// Add an answer
	rr, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("failed to create RR: %v", err)
	}
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
	if err != nil {
		t.Fatalf("encodeCacheAnswer failed: %v", err)
	}

	// Verify format
	if len(encoded) < headerSize {
		t.Fatalf("encoded data too short: %d bytes", len(encoded))
	}

	// Check version byte
	if encoded[0] != binaryFormatVersion {
		t.Errorf("version byte = %d, want %d", encoded[0], binaryFormatVersion)
	}

	// Check flags byte
	expectedFlags := byte(flagPrefetchBit)
	if encoded[1] != expectedFlags {
		t.Errorf("flags byte = %d, want %d", encoded[1], expectedFlags)
	}

	// Decode
	decoded, err := decodeCacheAnswer(encoded)
	if err != nil {
		t.Fatalf("decodeCacheAnswer failed: %v", err)
	}

	// Verify fields
	if decoded.Timestamp.Unix() != original.Timestamp.Unix() {
		t.Errorf("timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}

	if decoded.PrefetchEligible != original.PrefetchEligible {
		t.Errorf("prefetchEligible = %v, want %v", decoded.PrefetchEligible, original.PrefetchEligible)
	}

	// Verify DNS message
	if len(decoded.Msg.Answer) != len(original.Msg.Answer) {
		t.Errorf("answer count = %d, want %d", len(decoded.Msg.Answer), len(original.Msg.Answer))
	}

	if decoded.Msg.Question[0].Name != original.Msg.Question[0].Name {
		t.Errorf("question name = %s, want %s", decoded.Msg.Question[0].Name, original.Msg.Question[0].Name)
	}

	if decoded.Msg.Question[0].Qtype != original.Msg.Question[0].Qtype {
		t.Errorf("question type = %d, want %d", decoded.Msg.Question[0].Qtype, original.Msg.Question[0].Qtype)
	}
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
	if err != nil {
		t.Fatalf("encodeCacheAnswer failed: %v", err)
	}

	// Check flags byte (should be 0)
	if encoded[1] != 0 {
		t.Errorf("flags byte = %d, want 0", encoded[1])
	}

	// Decode
	decoded, err := decodeCacheAnswer(encoded)
	if err != nil {
		t.Fatalf("decodeCacheAnswer failed: %v", err)
	}

	if decoded.PrefetchEligible != false {
		t.Errorf("prefetchEligible = %v, want false", decoded.PrefetchEligible)
	}
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
			if err == nil {
				t.Error("expected error, got nil")
			}
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
	for i := 0; i < 100; i++ {
		encoded, err := encodeCacheAnswer(item)
		if err != nil {
			t.Fatalf("iteration %d: encodeCacheAnswer failed: %v", i, err)
		}

		// Verify first byte is always version
		if encoded[0] != binaryFormatVersion {
			t.Errorf("iteration %d: version byte = %d, want %d", i, encoded[0], binaryFormatVersion)
		}

		// Decode to verify correctness
		decoded, err := decodeCacheAnswer(encoded)
		if err != nil {
			t.Fatalf("iteration %d: decodeCacheAnswer failed: %v", i, err)
		}

		if decoded.Msg.Question[0].Name != "pool.test." {
			t.Errorf("iteration %d: corrupted data", i)
		}
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
	if err != nil {
		t.Fatalf("first encode failed: %v", err)
	}

	// Save a copy of the original encoded data
	original := make([]byte, len(encoded1))
	copy(original, encoded1)

	// Mutate the returned slice to verify it's independent of the pool
	for i := range encoded1 {
		encoded1[i] = 0xFF
	}

	// Verify the mutated buffer is now garbage and fails to decode
	_, err = decodeCacheAnswer(encoded1)
	if err == nil {
		t.Error("expected decode of mutated buffer to fail, but it succeeded")
	}

	// Second encode - should succeed and produce the same result as the first
	encoded2, err := encodeCacheAnswer(item)
	if err != nil {
		t.Fatalf("second encode failed: %v", err)
	}

	// Verify second encode matches the original (not corrupted by mutation)
	if len(encoded2) != len(original) {
		t.Fatalf("length mismatch: got %d, want %d", len(encoded2), len(original))
	}

	for i := range original {
		if encoded2[i] != original[i] {
			t.Errorf("byte %d: got %02x, want %02x (mutation leaked into pool)", i, encoded2[i], original[i])
		}
	}

	// Verify we can still decode the second result
	decoded, err := decodeCacheAnswer(encoded2)
	if err != nil {
		t.Fatalf("decode after mutation failed: %v", err)
	}

	if decoded.Msg.Question[0].Name != "independent.test." {
		t.Errorf("decoded name = %s, want independent.test.", decoded.Msg.Question[0].Name)
	}
}

func TestEncodeConcurrent(t *testing.T) {
	// Test concurrent encoding to catch pool-related race conditions
	// Each goroutine gets its own dns.Msg to avoid racing on shared message internals
	const numGoroutines = 50
	const numIterations = 100

	errs := make(chan error, numGoroutines)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
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

			for i := 0; i < numIterations; i++ {
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
		t.Fatalf("concurrent encode/decode failed: %v", err)
	}
}
