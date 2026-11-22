package rdns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestDOQSimple(t *testing.T) {
	d, err := NewDoQClient("test-doq", "dns-unfiltered.adguard.com:8853", DoQClientOptions{})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	id := q.Id
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
	require.Equal(t, id, r.Id)
}

func TestDOQError(t *testing.T) {
	d, err := NewDoQClient("test-doq", "127.0.0.1:0", DoQClientOptions{})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	id := q.Id
	_, err = d.Resolve(q, ClientInfo{})
	require.Error(t, err)
	require.Equal(t, id, q.Id) // Shouldn't touch the ID in the query
}

// A DoQ upstream that answers with a question other than the one that was
// asked must be rejected, and nothing may be stored in a cache placed in front
// of it. The QUIC stream identifies which stream carried the response, not that
// the DNS message in it answers the question. See issue #595.
func TestDOQWrongQuestionResponse(t *testing.T) {
	// Upstream that always answers for attacker.example., regardless of the query
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetQuestion("attacker.example.", dns.TypeA)
			a.Response = true
			a.Id = q.Id
			rr, err := dns.NewRR("attacker.example. 3600 IN A 6.6.6.6")
			if err != nil {
				return nil, err
			}
			a.Answer = []dns.RR{rr}
			return a, nil
		},
	}

	addr, err := getUDPLnAddress()
	require.NoError(t, err)
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	ln := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() { _ = ln.Start() }()
	defer ln.Stop()
	time.Sleep(500 * time.Millisecond)

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	client, err := NewDoQClient("test-doq-client", addr, DoQClientOptions{TLSConfig: tlsClientConfig})
	require.NoError(t, err)

	cache := NewCache("test-cache", client, CacheOptions{})

	q := new(dns.Msg)
	q.SetQuestion("victim.example.", dns.TypeA)

	// The mismatched response must not be passed on to the caller
	_, err = cache.Resolve(q.Copy(), ClientInfo{})
	require.Error(t, err)

	// Nothing should have been cached under the victim's key, so a second query
	// hits the upstream again rather than being served a poisoned entry.
	_, err = cache.Resolve(q.Copy(), ClientInfo{})
	require.Error(t, err)
	require.Equal(t, 2, upstream.HitCount())
}

// TestDoQClient0RTTHoldsNonReplayableOpcode is the client-side half of the rule
// enforced by the DoQ listener: with 0-RTT enabled, everything written before
// the handshake completes goes out as replayable early data, and RFC 9250 4.5
// allows only QUERY and NOTIFY there. A DNS UPDATE must wait instead.
//
// The server here records, for every query it receives, whether the stream was
// accepted before its handshake completed. Closing the connection from the
// server side forces the client to redial, and since it holds a session ticket
// by then the redial resumes with 0-RTT. The QUERY case is the control: without
// it the test would pass just as happily if 0-RTT were never used at all.
func TestDoQClient0RTTHoldsNonReplayableOpcode(t *testing.T) {
	server := startDoQEarlyRecorder(t, doqRecorderOptions{})

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	d, err := NewDoQClient("test-doq", server.addr, DoQClientOptions{TLSConfig: tlsClientConfig, Use0RTT: true})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// The first query completes a full handshake and leaves a session ticket
	// behind for the redials below to resume from.
	_, err = d.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// Control: a QUERY is replayable and does go out as early data.
	server.closeCurrentConn(t)
	_, err = d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.True(t, server.last(t).early, "QUERY was not sent as 0-RTT; this test cannot prove anything about the UPDATE below")

	// An UPDATE takes the same path but must be held back until the handshake
	// completes.
	server.closeCurrentConn(t)
	update := new(dns.Msg)
	update.SetUpdate("replay.lab.")
	_, err = d.Resolve(update, ClientInfo{})
	require.NoError(t, err)
	require.False(t, server.last(t).early, "UPDATE was sent as replayable 0-RTT data")
}

// doqEarlyRecorder is a minimal DoQ server that answers queries and records
// whether each one arrived before its connection finished the handshake, ie.
// as 0-RTT data.
type doqEarlyRecorder struct {
	addr     string
	delay    time.Duration
	conn     atomic.Pointer[quic.Conn]
	accepted atomic.Int32
	mu       sync.Mutex
	seen     []doqRecordedQuery
	stop     func()
}

type doqRecorderOptions struct {
	addr       string        // listen address, a random local port if empty
	maxStreams int64         // concurrent streams per connection, 0 for the quic-go default
	delay      time.Duration // before answering each query
}

type doqRecordedQuery struct {
	opcode int
	early  bool
}

func startDoQEarlyRecorder(t *testing.T, opt doqRecorderOptions) *doqEarlyRecorder {
	t.Helper()
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)
	tlsServerConfig.NextProtos = []string{"doq"}

	if opt.addr == "" {
		opt.addr = "127.0.0.1:0"
	}
	lAddr, err := net.ResolveUDPAddr("udp", opt.addr)
	require.NoError(t, err)
	udpConn, err := net.ListenUDP("udp", lAddr)
	require.NoError(t, err)
	transport := &quic.Transport{Conn: udpConn}
	ln, err := transport.ListenEarly(tlsServerConfig, &quic.Config{
		Allow0RTT:          true,
		MaxIdleTimeout:     time.Minute,
		MaxIncomingStreams: opt.maxStreams,
	})
	require.NoError(t, err)

	r := &doqEarlyRecorder{addr: udpConn.LocalAddr().String(), delay: opt.delay}
	var once sync.Once
	r.stop = func() { once.Do(func() { ln.Close(); transport.Close(); udpConn.Close() }) }
	t.Cleanup(r.stop)
	go r.accept(ln)
	return r
}

func (r *doqEarlyRecorder) accept(ln *quic.EarlyListener) {
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		r.conn.Store(conn)
		r.accepted.Add(1)
		go r.handleConn(conn)
	}
}

func (r *doqEarlyRecorder) handleConn(conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		early := true
		select {
		case <-conn.HandshakeComplete():
			early = false
		default:
		}
		go r.handleStream(stream, early)
	}
}

func (r *doqEarlyRecorder) handleStream(stream *quic.Stream, early bool) {
	defer stream.Close()
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		return
	}
	b := make([]byte, length)
	if _, err := io.ReadFull(stream, b); err != nil {
		return
	}
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		return
	}
	r.mu.Lock()
	r.seen = append(r.seen, doqRecordedQuery{opcode: q.Opcode, early: early})
	r.mu.Unlock()
	time.Sleep(r.delay)

	a := new(dns.Msg)
	a.SetReply(q)
	p, err := a.Pack()
	if err != nil {
		return
	}
	out := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(out, uint16(len(p)))
	copy(out[2:], p)
	_, _ = stream.Write(out)
}

// closeCurrentConn drops the connection the client is using, so its next query
// has to redial. With a session ticket in hand that redial uses 0-RTT.
func (r *doqEarlyRecorder) closeCurrentConn(t *testing.T) {
	t.Helper()
	conn := r.conn.Load()
	require.NotNil(t, conn, "no connection has been accepted yet")
	require.NoError(t, conn.CloseWithError(DOQNoError, ""))
	// Give the CONNECTION_CLOSE time to reach the client, so that its next
	// OpenStream fails and triggers the redial rather than racing it.
	time.Sleep(200 * time.Millisecond)
}

func (r *doqEarlyRecorder) last(t *testing.T) doqRecordedQuery {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.NotEmpty(t, r.seen, "server received no queries")
	return r.seen[len(r.seen)-1]
}

// idle-timeout has to reach the QUIC config as MaxIdleTimeout. Zero leaves it
// unset so quic-go applies its own default.
func TestDoQClientIdleTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  time.Duration
		want time.Duration
	}{
		{"set", 45 * time.Second, 45 * time.Second},
		{"unset keeps the library default", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewDoQClient("test-doq", "127.0.0.1:8853", DoQClientOptions{IdleTimeout: tc.opt})
			require.NoError(t, err)
			require.Equal(t, tc.want, c.connection.config.MaxIdleTimeout)
		})
	}
}

// Queries to an upstream that does not answer must each fail after about the
// query timeout, not queue up behind one another's connection attempts. That
// includes the query that started the attempt, even when the attempt itself
// runs longer.
func TestDOQDeadUpstream(t *testing.T) {
	const timeout = 300 * time.Millisecond
	dead, err := net.ListenPacket("udp", "127.0.0.1:0") // never answers
	require.NoError(t, err)
	defer dead.Close()
	d, err := NewDoQClient("test-doq-dead", dead.LocalAddr().String(), DoQClientOptions{QueryTimeout: timeout})
	require.NoError(t, err)
	d.connection.config.HandshakeIdleTimeout = 5 * timeout
	t.Cleanup(func() {
		// Let the dial the queries gave up on finish, so it doesn't outlive the test.
		d.connection.mu.Lock()
		dial := d.connection.dial
		d.connection.mu.Unlock()
		if dial != nil {
			<-dial.done
		}
	})
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	start := time.Now()
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			_, err := d.Resolve(q, ClientInfo{})
			var timedOut net.Error
			if !errors.As(err, &timedOut) || !timedOut.Timeout() {
				t.Errorf("expected a timeout, got %v", err)
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, timeout)
	require.Less(t, elapsed, 3*timeout) // one at a time takes 6x
}

// A link-local literal, as given in bootstrap-address, must keep its zone or
// it can't be dialled.
func TestDoQResolveUDPAddrZone(t *testing.T) {
	a, err := resolveUDPAddr(context.Background(), "[fe80::1%lo]:853", true)
	require.NoError(t, err)
	require.Equal(t, "[fe80::1%lo]:853", a.String())
}

// More concurrent queries than the server allows streams must wait for a
// stream on the connection they share, not tear it down and fail the queries
// still in flight on it.
func TestDoQClientStreamLimit(t *testing.T) {
	server := startDoQEarlyRecorder(t, doqRecorderOptions{maxStreams: 2, delay: 100 * time.Millisecond})

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	d, err := NewDoQClient("test-doq", server.addr, DoQClientOptions{TLSConfig: tlsClientConfig})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, err := d.Resolve(q, ClientInfo{}); err != nil {
				t.Errorf("query failed: %v", err)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int32(1), server.accepted.Load(), "the connection was replaced")
}

// When the server rejects 0-RTT, here because it restarted and can't read the
// client's session ticket any more, the queries sent as early data were
// discarded and have to be sent again once the handshake completes.
func TestDoQClient0RTTRejected(t *testing.T) {
	server := startDoQEarlyRecorder(t, doqRecorderOptions{})

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	d, err := NewDoQClient("test-doq", server.addr, DoQClientOptions{TLSConfig: tlsClientConfig, Use0RTT: true})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Pick up a session ticket
	_, err = d.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	server.closeCurrentConn(t)
	server.stop()
	server = startDoQEarlyRecorder(t, doqRecorderOptions{addr: server.addr})

	_, err = d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.False(t, server.last(t).early)
}
