package rdns

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRequestDedup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var ci ClientInfo
		r := &TestResolver{
			ResolveFunc: func(*dns.Msg, ClientInfo) (*dns.Msg, error) {
				time.Sleep(time.Second)
				return nil, nil
			},
		}

		g := NewRequestDedup("test-dedup", r)
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)

		// Send a batch of queries
		var wg sync.WaitGroup
		for range 10 {
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
	})
}

func TestRequestDedupDOBitNotCoalesced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var ci ClientInfo
		r := &TestResolver{
			ResolveFunc: func(q *dns.Msg, _ ClientInfo) (*dns.Msg, error) {
				time.Sleep(time.Second)
				a := new(dns.Msg)
				a.SetReply(q)
				return a, nil
			},
		}
		g := NewRequestDedup("test-dedup", r)

		var wg sync.WaitGroup

		// Query 1: DO=0
		q1 := new(dns.Msg)
		q1.SetQuestion("example.com.", dns.TypeA)
		wg.Add(1)
		go func() { defer wg.Done(); g.Resolve(q1, ci) }()
		synctest.Wait() // q1 is now in-flight upstream

		// Query 2: same name/type but DO=1 — must NOT coalesce with q1
		q2 := new(dns.Msg)
		q2.SetQuestion("example.com.", dns.TypeA)
		q2.SetEdns0(4096, true)
		wg.Add(1)
		go func() { defer wg.Done(); g.Resolve(q2, ci) }()
		synctest.Wait()

		// Both queries must have reached the upstream resolver independently.
		// If q2 had coalesced onto q1 it would be parked on req.done and the
		// hit count would be 1.
		require.Equal(t, 2, r.HitCount(), "DO=1 query was coalesced onto in-flight DO=0 query")

		wg.Wait()
	})
}

func TestRequestDedupRestoresIdAndQuestion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var ci ClientInfo
		r := &TestResolver{
			ResolveFunc: func(q *dns.Msg, _ ClientInfo) (*dns.Msg, error) {
				time.Sleep(time.Second)
				a := new(dns.Msg)
				a.SetReply(q)
				return a, nil
			},
		}
		g := NewRequestDedup("test-dedup", r)

		type result struct {
			a   *dns.Msg
			err error
		}
		c1, c2 := make(chan result, 1), make(chan result, 1)

		// Query 1: Id=100, mixed-case name
		q1 := new(dns.Msg)
		q1.SetQuestion("Example.COM.", dns.TypeA)
		q1.Id = 100
		go func() { a, err := g.Resolve(q1, ci); c1 <- result{a, err} }()
		synctest.Wait() // q1 is the leader, now blocked upstream

		// Query 2: Id=200, different case — must coalesce onto q1
		q2 := new(dns.Msg)
		q2.SetQuestion("example.com.", dns.TypeA)
		q2.Id = 200
		go func() { a, err := g.Resolve(q2, ci); c2 <- result{a, err} }()
		synctest.Wait() // q2 is parked on req.done

		// Only the leader hit upstream
		require.Equal(t, 1, r.HitCount())

		r1, r2 := <-c1, <-c2
		require.NoError(t, r1.err)
		require.NoError(t, r2.err)

		// Each caller gets its own transaction ID and Question section back
		require.Equal(t, uint16(100), r1.a.Id)
		require.Equal(t, "Example.COM.", r1.a.Question[0].Name)
		require.Equal(t, uint16(200), r2.a.Id)
		require.Equal(t, "example.com.", r2.a.Question[0].Name)
	})
}
