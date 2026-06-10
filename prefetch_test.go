package rdns

import (
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
