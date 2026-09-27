package rdns

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
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
	p := NewPipeline("test", "localhost:53", testDialer(df), time.Second, 0)

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
	p := NewPipeline("test", "localhost:53", testDialer(df), 50*time.Millisecond, 0)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A query per caller, as every client makes one to pack into.
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
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

// A response that echoes back a matching Question must be accepted.
func TestPipelineQuestionMatch(t *testing.T) {
	server, client := net.Pipe()
	go func() { // upstream that echoes the question and adds an answer
		conn := &dns.Conn{Conn: server}
		query, err := conn.ReadMsg()
		if err != nil {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(query)
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		}}
		_ = conn.WriteMsg(resp)
	}()
	t.Cleanup(func() { server.Close() })

	df := func(address string) (*dns.Conn, error) {
		return &dns.Conn{Conn: client}, nil
	}
	p := NewPipeline("test", "localhost:53", testDialer(df), time.Second, 0)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	a, err := p.Resolve(q)
	require.NoError(t, err)
	require.Len(t, a.Answer, 1)
}

// A spoofed response with QDCOUNT=0 must be rejected even when the transaction
// ID matches, instead of silently bypassing the RFC 5452 9.1 / RFC 7858 3.3
// anti-spoofing question check.
func TestPipelineRejectEmptyQuestion(t *testing.T) {
	server, client := net.Pipe()
	go func() { // upstream that replies with a matching ID but no Question
		conn := &dns.Conn{Conn: server}
		query, err := conn.ReadMsg()
		if err != nil {
			return
		}
		resp := new(dns.Msg)
		resp.Id = query.Id // matching transaction ID, as a spoofer would brute-force
		resp.Response = true
		// Deliberately no Question section (QDCOUNT=0).
		resp.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		}}
		_ = conn.WriteMsg(resp)
	}()
	t.Cleanup(func() { server.Close() })

	df := func(address string) (*dns.Conn, error) {
		return &dns.Conn{Conn: client}, nil
	}
	p := NewPipeline("test", "localhost:53", testDialer(df), time.Second, 0)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err := p.Resolve(q)
	require.Error(t, err, "response with empty question section must be rejected")
}

// The idle timeout tears down a connection that has gone quiet, so the next
// query has to dial again. Without a configurable value this could only be
// exercised by waiting out the 10s default.
func TestPipelineIdleTimeout(t *testing.T) {
	var dials atomic.Int64
	var mu sync.Mutex
	var servers []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range servers {
			c.Close()
		}
	})

	df := func(address string) (*dns.Conn, error) {
		dials.Add(1)
		server, client := net.Pipe()
		mu.Lock()
		servers = append(servers, server)
		mu.Unlock()
		go func() { // upstream that reads queries but never answers
			buf := make([]byte, 4096)
			for {
				if _, err := server.Read(buf); err != nil {
					return
				}
			}
		}()
		return &dns.Conn{Conn: client}, nil
	}
	p := NewPipeline("test", "localhost:53", testDialer(df), 20*time.Millisecond, 10*time.Millisecond)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err := p.Resolve(q)
	require.Error(t, err, "upstream never answers")
	require.Equal(t, int64(1), dials.Load())

	// Wait out the idle timeout, which closes the connection. The next query
	// has to establish a new one.
	require.Eventually(t, func() bool {
		_, _ = p.Resolve(q)
		return dials.Load() > 1
	}, time.Second, 10*time.Millisecond, "idle connection was not torn down")
}

// A zero idle timeout keeps the package default rather than expiring
// connections immediately.
func TestPipelineIdleTimeoutDefault(t *testing.T) {
	p := NewPipeline("test", "localhost:53", testDialer(func(string) (*dns.Conn, error) {
		return nil, errors.New("not dialed")
	}), 0, 0)
	require.Equal(t, defaultIdleTimeout, p.idle)
	require.Equal(t, defaultQueryTimeout, p.timeout)
}

// The queue sends a query out under an ID of its own choosing, since the IDs
// clients pick collide on a shared connection, and the answer has to come back
// under the one the client asked with. Two queries carrying the same ID are
// told apart and each gets its own answer.
func TestPipelineRestoresQueryID(t *testing.T) {
	server, client := net.Pipe()
	// Collected rather than sent over a channel: the upstream goroutine outlives
	// the assertions below, and a query arriving after them must not find a
	// closed channel or a full one.
	var mu sync.Mutex
	var upstreamIDs []uint16
	go func() { // upstream answering each query with the name it asked for
		conn := &dns.Conn{Conn: server}
		for {
			query, err := conn.ReadMsg()
			if err != nil {
				return
			}
			mu.Lock()
			upstreamIDs = append(upstreamIDs, query.Id)
			mu.Unlock()
			resp := new(dns.Msg)
			resp.SetReply(query)
			resp.Answer = []dns.RR{&dns.TXT{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{query.Question[0].Name},
			}}
			_ = conn.WriteMsg(resp)
		}
	}()
	t.Cleanup(func() { server.Close() })

	df := func(address string) (*dns.Conn, error) {
		return &dns.Conn{Conn: client}, nil
	}
	p := NewPipeline("test", "localhost:53", testDialer(df), time.Second, 0)

	// Both queries carry the same ID, which is what a listener serving two
	// clients at once hands over.
	const sharedID = 0x1234
	type result struct {
		a   *dns.Msg
		err error
	}
	results := make(chan result, 2)
	for _, name := range []string{"one.example.com.", "two.example.com."} {
		go func() {
			q := new(dns.Msg)
			q.SetQuestion(name, dns.TypeTXT)
			q.Id = sharedID
			a, err := p.Resolve(q)
			results <- result{a, err}
		}()
	}

	for range 2 {
		got := <-results
		require.NoError(t, got.err)
		require.Equal(t, uint16(sharedID), got.a.Id, "the answer must carry the ID the client asked with")
		require.Len(t, got.a.Answer, 1)
		// The answer has to be the one for the question that was asked, not
		// the other query's, which is what the queue's own IDs are for.
		require.Equal(t, got.a.Question[0].Name, got.a.Answer[0].Header().Name)
	}

	// The IDs on the wire are the queue's, not the one both clients used.
	mu.Lock()
	defer mu.Unlock()
	var sawShared int
	for _, id := range upstreamIDs {
		if id == sharedID {
			sawShared++
		}
	}
	require.LessOrEqual(t, sawShared, 1, "both queries went out under the client's colliding ID")
}
