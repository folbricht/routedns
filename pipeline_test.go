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
	p := NewPipeline("test", "localhost:53", testDialer(df), time.Second)

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
	p := NewPipeline("test", "localhost:53", testDialer(df), time.Second)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err := p.Resolve(q)
	require.Error(t, err, "response with empty question section must be rejected")
}
