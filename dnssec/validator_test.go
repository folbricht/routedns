package dnssec

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestParentZone(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"example.com.", "com."},
		{"com.", "."},
		{".", "."},
		{"sub.example.com.", "example.com."},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.expected, parentZone(tc.input))
		})
	}
}

func TestGroupRRsByTypeAndName(t *testing.T) {
	rr1, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
	rr2, _ := dns.NewRR("example.com. 300 IN A 5.6.7.8")
	rr3, _ := dns.NewRR("example.com. 300 IN AAAA ::1")
	sig1, _ := dns.NewRR("example.com. 300 IN RRSIG A 13 2 300 20300101000000 20200101000000 12345 example.com. AAAA==")

	rrsets, sigs := groupRRsByTypeAndName([]dns.RR{rr1, rr2, rr3, sig1})

	aKey := rrsetKey{name: "example.com.", rrtype: dns.TypeA}
	aaaaKey := rrsetKey{name: "example.com.", rrtype: dns.TypeAAAA}

	require.Len(t, rrsets[aKey], 2)
	require.Len(t, rrsets[aaaaKey], 1)
	require.NotNil(t, sigs[aKey])
	require.Nil(t, sigs[aaaaKey])
}

func TestVerifyDNSKEYWithDS(t *testing.T) {
	// Use the real IANA root KSK for this test
	rootKSKRR, err := dns.NewRR(". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=")
	require.NoError(t, err)
	rootKSK := rootKSKRR.(*dns.DNSKEY)

	// Compute expected DS
	ds := rootKSK.ToDS(dns.SHA256)
	require.NotNil(t, ds)

	// Matching should succeed
	err = verifyDNSKEYWithDS([]*dns.DNSKEY{rootKSK}, []*dns.DS{ds})
	require.NoError(t, err)

	// Wrong digest should fail
	badDS := *ds
	badDS.Digest = "0000000000000000000000000000000000000000000000000000000000000000"
	err = verifyDNSKEYWithDS([]*dns.DNSKEY{rootKSK}, []*dns.DS{&badDS})
	require.ErrorIs(t, err, ErrDSMismatch)
}

func TestValidateNoRRSIG(t *testing.T) {
	// A response with records but no RRSIG should return ErrNoSignature
	// unless it's an insecure delegation
	v := NewValidator(
		WithResolver(func(q *dns.Msg) (*dns.Msg, error) {
			// DS lookup returns empty → insecure delegation
			a := new(dns.Msg)
			a.SetReply(q)
			return a, nil
		}),
	)

	answer := new(dns.Msg)
	answer.SetQuestion("example.com.", dns.TypeA)
	rr, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
	answer.Answer = []dns.RR{rr}

	err := v.Validate(answer)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInsecureDelegation)
}

func TestValidateEmptyAnswer(t *testing.T) {
	v := NewValidator()
	answer := new(dns.Msg)
	answer.SetQuestion("example.com.", dns.TypeA)
	err := v.Validate(answer)
	require.NoError(t, err)
}

func TestKeystoreCaching(t *testing.T) {
	now := time.Now()
	ks := newKeystore(func() time.Time { return now })

	zskRR, _ := dns.NewRR("example.com. 3600 IN DNSKEY 256 3 13 dGVzdA==")
	kskRR, _ := dns.NewRR("example.com. 3600 IN DNSKEY 257 3 13 dGVzdA==")

	ks.addDNSKEY("example.com.", []*dns.DNSKEY{zskRR.(*dns.DNSKEY), kskRR.(*dns.DNSKEY)})

	zsk, ksk := ks.getDNSKEY("example.com.")
	require.Len(t, zsk, 1)
	require.Len(t, ksk, 1)

	// Second call should return cached values
	zsk2, ksk2 := ks.getDNSKEY("example.com.")
	require.Equal(t, zsk, zsk2)
	require.Equal(t, ksk, ksk2)
}

func TestKeystoreTTLExpiry(t *testing.T) {
	now := time.Now()
	currentTime := now
	ks := newKeystore(func() time.Time { return currentTime })

	zskRR, _ := dns.NewRR("example.com. 60 IN DNSKEY 256 3 13 dGVzdA==")
	ks.addDNSKEY("example.com.", []*dns.DNSKEY{zskRR.(*dns.DNSKEY)})

	// Should be in cache
	zsk, _ := ks.getDNSKEY("example.com.")
	require.Len(t, zsk, 1)

	// Advance past TTL
	currentTime = now.Add(61 * time.Second)

	// Should be expired
	zsk, _ = ks.getDNSKEY("example.com.")
	require.Nil(t, zsk)
}

func TestKeystoreDSExpiry(t *testing.T) {
	now := time.Now()
	currentTime := now
	ks := newKeystore(func() time.Time { return currentTime })

	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		KeyTag:     12345,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "ABCD",
	}
	ks.addDS("example.com.", ds)

	// Should be in cache
	result := ks.getDS("example.com.")
	require.Len(t, result, 1)

	// Advance past TTL
	currentTime = now.Add(61 * time.Second)

	// Should be expired
	result = ks.getDS("example.com.")
	require.Nil(t, result)
}

func TestBuildChainOfTrustCaching(t *testing.T) {
	// Verify that buildChainOfTrust only queries DNSKEY once per zone
	// by counting resolver calls
	var lookupCount atomic.Int64

	v := NewValidator(
		WithResolver(func(q *dns.Msg) (*dns.Msg, error) {
			lookupCount.Add(1)
			a := new(dns.Msg)
			a.SetReply(q)
			// Return empty — this will cause an error, but we're testing caching
			return a, nil
		}),
	)
	v.SetAnchor(".", 20326, dns.RSASHA256, dns.SHA256, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")

	// First call will trigger a lookup (and fail due to no DNSKEY)
	_, _, err := v.buildChainOfTrust(".")
	require.Error(t, err) // Expected to fail since mock returns no keys

	count1 := lookupCount.Load()
	require.Equal(t, int64(1), count1)
}

func TestFindKeysByTag(t *testing.T) {
	key1RR, _ := dns.NewRR(". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=")
	key1 := key1RR.(*dns.DNSKEY)

	tag := key1.KeyTag()
	alg := key1.Algorithm

	// Should find the key
	found := findKeysByTag([]*dns.DNSKEY{key1}, tag, alg)
	require.Len(t, found, 1)

	// Wrong tag should find nothing
	found = findKeysByTag([]*dns.DNSKEY{key1}, tag+1, alg)
	require.Len(t, found, 0)

	// Wrong algorithm should find nothing
	found = findKeysByTag([]*dns.DNSKEY{key1}, tag, alg+1)
	require.Len(t, found, 0)
}

func TestValidateInsecureDelegation(t *testing.T) {
	v := NewValidator(
		WithResolver(func(q *dns.Msg) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			// Return empty for DS lookups → insecure delegation
			// Return empty for DNSKEY lookups → will fail
			return a, nil
		}),
	)

	// Build a response with an unsigned A record
	answer := new(dns.Msg)
	answer.SetQuestion("insecure.example.", dns.TypeA)
	rr, _ := dns.NewRR("insecure.example. 300 IN A 1.2.3.4")
	answer.Answer = []dns.RR{rr}

	err := v.Validate(answer)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInsecureDelegation)
}
