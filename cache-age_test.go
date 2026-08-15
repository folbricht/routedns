package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestCacheAge(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC).UnixNano()

	for _, tc := range []struct {
		name   string
		stored time.Duration // relative to now, negative means earlier
		want   uint32
	}{
		{"just stored", 0, 0},
		{"under a second", -900 * time.Millisecond, 0},
		{"a second", -time.Second, 1},
		{"rounds down", -1900 * time.Millisecond, 1},
		{"an hour", -time.Hour, 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, cacheAge(now, now+int64(tc.stored)))
		})
	}
}

// A record timestamped ahead of now must count as new rather than wrapping
// into a huge age, which would age out every record it holds. A backwards
// clock step does this, as does a cache file or a shared Redis written by a
// machine whose clock runs ahead.
func TestCacheAgeIgnoresTimestampsInTheFuture(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC).UnixNano()

	for _, ahead := range []time.Duration{time.Nanosecond, time.Second, 24 * time.Hour} {
		require.Zero(t, cacheAge(now, now+int64(ahead)),
			"a record stored %s ahead of now must not age", ahead)
	}
}

func ageTestAnswer(t *testing.T) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a := new(dns.Msg)
	a.SetReply(q)

	answer, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	require.NoError(t, err)
	ns, err := dns.NewRR("example.com. 600 IN NS ns1.example.com.")
	require.NoError(t, err)
	extra, err := dns.NewRR("ns1.example.com. 900 IN A 192.0.2.53")
	require.NoError(t, err)

	a.Answer = []dns.RR{answer}
	a.Ns = []dns.RR{ns}
	a.Extra = []dns.RR{extra}
	return a
}

func TestAgeCachedAnswer(t *testing.T) {
	a := ageTestAnswer(t)

	q := new(dns.Msg)
	q.SetQuestion("ExAmPlE.CoM.", dns.TypeA) // the case the client used
	q.Id = 4242

	require.True(t, ageCachedAnswer(a, q, 60))

	// The query's ID and the case of its question come back.
	require.Equal(t, uint16(4242), a.Id)
	require.Equal(t, "ExAmPlE.CoM.", a.Question[0].Name)

	// Every section is aged, not just the answer.
	require.Equal(t, uint32(240), a.Answer[0].Header().Ttl)
	require.Equal(t, uint32(540), a.Ns[0].Header().Ttl)
	require.Equal(t, uint32(840), a.Extra[0].Header().Ttl)
}

// An OPT record carries no TTL, so it must be left alone rather than aged out
// and taking the whole response with it.
func TestAgeCachedAnswerSkipsOPT(t *testing.T) {
	a := ageTestAnswer(t)
	a.SetEdns0(4096, false)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	require.True(t, ageCachedAnswer(a, q, 60))
	require.NotNil(t, a.IsEdns0(), "the OPT record must survive")
}

func TestAgeCachedAnswerReportsAgedOut(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// The answer record has the lowest TTL, so 300 is where it ages out.
	require.True(t, ageCachedAnswer(ageTestAnswer(t), q, 299))
	require.False(t, ageCachedAnswer(ageTestAnswer(t), q, 300))
	require.False(t, ageCachedAnswer(ageTestAnswer(t), q, 301))

	// A record in a later section ages out too.
	a := ageTestAnswer(t)
	a.Answer[0].Header().Ttl = 100000
	a.Ns[0].Header().Ttl = 100000
	require.False(t, ageCachedAnswer(a, q, 900), "the Extra record has aged out")
}

// The memory backend serves from a blob and Redis from its own record, but the
// answer either produces has to age identically.
func TestBackendsAgeIdentically(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	stored := time.Now().Add(-90 * time.Second)

	item := &cacheAnswer{Msg: ageTestAnswer(t), Timestamp: stored, Expiry: stored.Add(time.Hour)}

	mem := NewMemoryBackend(MemoryBackendOptions{GCPeriod: time.Hour})
	defer mem.Close()
	mem.Store(q, item)
	fromMemory, _, ok := mem.Lookup(q)
	require.True(t, ok)

	// Redis has no test server, so go through its codec directly and age the
	// result the way redisBackend.Lookup does.
	buf := make([]byte, 0, 2048)
	encoded, err := encodeCacheAnswer(buf, item)
	require.NoError(t, err)
	decoded, err := decodeCacheAnswer(encoded)
	require.NoError(t, err)
	require.True(t, ageCachedAnswer(decoded.Msg, q,
		cacheAge(time.Now().UnixNano(), decoded.Timestamp.UnixNano())))

	for i, rr := range fromMemory.Answer {
		require.Equal(t, rr.Header().Ttl, decoded.Msg.Answer[i].Header().Ttl)
	}
	require.Equal(t, uint32(210), fromMemory.Answer[0].Header().Ttl)
}
