package rdns

import (
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// waitForGoroutines polls runtime.NumGoroutine until it drops to at most
// the target or the deadline expires. require.Eventually cannot be used
// here because it evaluates the condition in a separate goroutine, which
// itself inflates the count.
func waitForGoroutines(t *testing.T, target int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= target {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("probe goroutines did not terminate: have %d, want <= %d", runtime.NumGoroutine(), target)
}

// TestFastestTCPNoGoroutineLeak verifies that probe goroutines always
// terminate and close their sockets even when the caller stops reading
// after the first result (wait-all=false). Previously the unbuffered
// result channel caused N-1 goroutines per query to block forever on
// send, leaking goroutines and any successfully-dialed sockets.
func TestFastestTCPNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	// Local TCP listener that accepts every probe so all goroutines
	// reach the channel-send path with an open socket.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var accepted, closed int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepted, 1)
			go func() {
				defer c.Close()
				// Read returns once the peer closes the connection.
				var buf [1]byte
				c.Read(buf[:])
				atomic.AddInt32(&closed, 1)
			}()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Upstream resolver returns several A records pointing at the listener.
	const numRecords = 8
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			for i := 0; i < numRecords; i++ {
				a.Answer = append(a.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP("127.0.0.1"),
				})
			}
			return a, nil
		},
	}

	r := NewFastestTCP("test-fastest", upstream, FastestTCPOptions{Port: port})

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, numRecords)

	// Every accepted probe connection must be closed by the probe side.
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&accepted) > 0 &&
			atomic.LoadInt32(&closed) == atomic.LoadInt32(&accepted)
	}, 2*time.Second, 10*time.Millisecond, "probe sockets were not closed")

	// Stop the accept loop, then verify all goroutines spawned during the
	// test have exited.
	ln.Close()
	waitForGoroutines(t, before, 2*time.Second)
}

// TestFastestTCPProbeCap verifies that responses with more A/AAAA records
// than fastestTCPMaxProbes do not spawn an unbounded number of probe
// goroutines and that the merge-back into the original answer does not
// panic when the cap is hit.
func TestFastestTCPProbeCap(t *testing.T) {
	// Use a port that refuses connections so probes fail fast without
	// needing a real listener; we only care that Resolve returns
	// without panicking and without leaking goroutines.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close() // closed listener -> dials get ECONNREFUSED

	const numRecords = fastestTCPMaxProbes + 20
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			for i := 0; i < numRecords; i++ {
				a.Answer = append(a.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP("127.0.0.1"),
				})
			}
			return a, nil
		},
	}

	r := NewFastestTCP("test-fastest", upstream, FastestTCPOptions{Port: port, WaitAll: true})

	before := runtime.NumGoroutine()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, a.Answer, numRecords)

	waitForGoroutines(t, before, 2*time.Second)
}
