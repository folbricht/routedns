package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A record timestamped ahead of now has to count as new rather than wrapping
// into a huge age. The Redis backend used to convert a negative float to
// uint32 here, which made a record stored a minute in the future measure as
// 4294967237 seconds old, past every TTL, so nothing written by a machine
// whose clock ran ahead could be served.
func TestCacheAgeIgnoresTimestampsInTheFuture(t *testing.T) {
	now := time.Now().UnixNano()
	require.Zero(t, cacheAge(now, now+int64(time.Minute)))
	require.Equal(t, uint32(60), cacheAge(now, now-int64(time.Minute)))
}

// Both backends decode a stored entry differently but have to age it the same
// way. The response carries an OPT record, which has no TTL and so must be
// left out of the ageing: counting it would age out every EDNS0 response the
// moment it was cached.
func TestBackendsAgeIdentically(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	answer := new(dns.Msg)
	answer.SetReply(q)
	for _, rr := range []string{
		"example.com. 300 IN A 192.0.2.1",
		"example.com. 600 IN NS ns1.example.com.",
	} {
		parsed, err := dns.NewRR(rr)
		require.NoError(t, err)
		answer.Answer = append(answer.Answer, parsed)
	}
	answer.SetEdns0(4096, false)

	stored := time.Now().Add(-90 * time.Second)
	item := &cacheAnswer{Msg: answer, Timestamp: stored, Expiry: stored.Add(time.Hour)}

	mem := NewMemoryBackend(MemoryBackendOptions{GCPeriod: time.Hour})
	defer mem.Close()
	mem.Store(q, item)
	fromMemory, _, ok := mem.Lookup(q)
	require.True(t, ok, "an answer carrying an OPT record must still be served")
	require.Equal(t, uint32(210), fromMemory.Answer[0].Header().Ttl)
	require.NotNil(t, fromMemory.IsEdns0(), "the OPT record must survive")

	// Redis has no test server, so go through its codec and age the result the
	// way redisBackend.Lookup does. Both backends now encode the same way, so
	// this is the record the memory path just served, which is the point: they
	// must not disagree about how old an entry is. They used to, by up to a
	// second, because the redis format truncated its timestamp.
	encoded, err := newCacheBlob(lruKey{}, item)
	require.NoError(t, err)
	decoded, err := decodeRecord(encoded)
	require.NoError(t, err)
	require.True(t, ageCachedAnswer(decoded.Msg, q,
		cacheAge(time.Now().UnixNano(), decoded.Timestamp.UnixNano())))

	for i, rr := range fromMemory.Answer {
		require.Equal(t, rr.Header().Ttl, decoded.Msg.Answer[i].Header().Ttl)
	}
}
