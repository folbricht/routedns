package rdns

import (
	"runtime"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A dropped query (nil response, nil error) must be passed through
// without dereferencing the response.
func TestPrefetchDroppedQuery(t *testing.T) {
	r := NewPrefetch("test-prefetch", NewDropResolver("test-drop"), PrefetchOptions{})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Nil(t, a)
}

func TestPrefetchPassthrough(t *testing.T) {
	r := NewPrefetch("test-prefetch", &TestResolver{}, PrefetchOptions{})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotNil(t, a)
}

func TestExpirationCacheShards(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(old)
	})

	require.Equal(t, uint(4), expirationCacheShards(0))
	require.Equal(t, uint(4), expirationCacheShards(100))
	require.Equal(t, uint(0), expirationCacheShards(1))

	runtime.GOMAXPROCS(1)
	require.Equal(t, uint(0), expirationCacheShards(100))
}
