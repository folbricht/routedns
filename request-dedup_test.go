package rdns

import (
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRequestDedup(t *testing.T) {
	var ci ClientInfo
	r := &TestResolver{
		ResolveFunc: func(*dns.Msg, ClientInfo) (*dns.Msg, error) {
			time.Sleep(time.Second) // need to slow down to guarantee duplicates
			return nil, nil
		},
	}

	g := NewRequestDedup("test-dedup", r)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Send a batch of queries
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.Resolve(q, ci)
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	// Only one request should have hit the resolver
	require.Equal(t, 1, r.HitCount())
}
