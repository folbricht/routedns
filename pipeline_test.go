package rdns

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type testDialer func(address string) (*dns.Conn, error)

func (d testDialer) Dial(address string) (*dns.Conn, error) {
	return d(address)
}

func TestPipelineQueryTimeout(t *testing.T) {
	df := func(address string) (*dns.Conn, error) {
		time.Sleep(2 * time.Second)
		return nil, errors.New("failed")
	}
	p := NewPipeline("test", "localhost:53", testDialer(df), time.Second)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Send some queries to start the pipeline
	_, _ = p.Resolve(q)
	_, _ = p.Resolve(q)

	// Record when we sent the query in order to tell how long it took
	start := time.Now()
	_, err := p.Resolve(q)

	// Make sure we get a timeout error and it took the right amount to come back
	require.ErrorAs(t, err, &QueryTimeoutError{})
	require.WithinDuration(t, start.Add(time.Second), time.Now(), 10*time.Millisecond)
}

// Queries whose responses never arrive must not accumulate in the in-flight map.
func TestPipelineInFlightCleanup(t *testing.T) {
	server, client := net.Pipe()
	go func() { // upstream that reads queries but never answers
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { server.Close() })

	df := func(address string) (*dns.Conn, error) {
		return &dns.Conn{Conn: client}, nil
	}
	p := NewPipeline("test", "localhost:53", testDialer(df), 50*time.Millisecond)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Resolve(q)
			require.Error(t, err)
		}()
	}
	wg.Wait()

	p.inFlight.mu.Lock()
	n := len(p.inFlight.requests)
	p.inFlight.mu.Unlock()
	require.Equal(t, 0, n, "in-flight map should be empty after all callers timed out")
}
