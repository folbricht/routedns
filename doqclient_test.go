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
	server := startDoQEarlyRecorder(t)

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
// as 0-RTT data. It never answers queries for doqHangName, and reports why
// their streams ended on hangEnded.
type doqEarlyRecorder struct {
	addr      string
	transport *quic.Transport
	ln        *quic.EarlyListener
	conn      atomic.Pointer[quic.Conn]
	accepted  atomic.Int32
	hangEnded chan error
	mu        sync.Mutex
	seen      []doqRecordedQuery
}

const doqHangName = "hang.example."

type doqRecordedQuery struct {
	opcode int
	early  bool
}

func startDoQEarlyRecorder(t *testing.T) *doqEarlyRecorder {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	r := &doqEarlyRecorder{
		addr:      udpConn.LocalAddr().String(),
		transport: &quic.Transport{Conn: udpConn},
		hangEnded: make(chan error, 10),
	}
	t.Cleanup(func() { r.ln.Close(); r.transport.Close(); udpConn.Close() })
	r.listen(t)
	return r
}

// listen accepts connections with a new TLS config, and so new session ticket
// keys: tickets issued by an earlier listener can't be resumed.
func (r *doqEarlyRecorder) listen(t *testing.T) {
	t.Helper()
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)
	tlsServerConfig.NextProtos = []string{"doq"}
	ln, err := r.transport.ListenEarly(tlsServerConfig, &quic.Config{Allow0RTT: true, MaxIdleTimeout: time.Minute})
	require.NoError(t, err)
	r.ln = ln
	go r.accept(ln)
}

// restart replaces the listener on the same socket, as if the server had
// restarted, and resets the count of accepted connections.
func (r *doqEarlyRecorder) restart(t *testing.T) {
	t.Helper()
	require.NoError(t, r.ln.Close())
	r.accepted.Store(0)
	r.listen(t)
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
	if len(q.Question) > 0 && q.Question[0].Name == doqHangName {
		<-stream.Context().Done()
		r.hangEnded <- context.Cause(stream.Context())
		return
	}

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
	// attempt to open a stream fails and triggers the redial rather than
	// racing it.
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

// Queries beyond the upstream's stream limit go to a new connection. That
// must not close the full one under the queries still in flight on it.
func TestDOQStreamLimit(t *testing.T) {
	upstream := &TestResolver{ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
		time.Sleep(200 * time.Millisecond) // hold the streams open
		a := new(dns.Msg)
		a.SetReply(q)
		return a, nil
	}}
	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	d, err := NewDoQClient("test-doq-limit", startTestDoQListener(t, upstream), DoQClientOptions{TLSConfig: tlsConfig})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	var wg sync.WaitGroup
	for range 150 { // the listener allows 100 streams
		wg.Go(func() {
			if _, err := d.Resolve(q, ClientInfo{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

// A link-local literal, as given in bootstrap-address, must keep its zone or
// it can't be dialled. A socket bound to a specific address can only reach an
// upstream of the same family, so anything else is an error up front rather
// than a failed dial.
func TestDoQResolveUDPAddr(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		local    string
		want     string // empty for an error
	}{
		{"[fe80::1%lo]:853", "", "[fe80::1%lo]:853"},
		{"192.0.2.1:853", "0.0.0.0", "192.0.2.1:853"},
		{"[2001:db8::1]:853", "0.0.0.0", "[2001:db8::1]:853"},
		{"192.0.2.1:853", "2001:db8::10", ""},
		{"[2001:db8::1]:853", "192.0.2.10", ""},
	} {
		a, err := resolveUDPAddr(context.Background(), tc.endpoint, net.ParseIP(tc.local))
		if tc.want == "" {
			require.Error(t, err, "%s from %s", tc.endpoint, tc.local)
			continue
		}
		require.NoError(t, err, "%s from %s", tc.endpoint, tc.local)
		require.Equal(t, tc.want, a.String())
	}
}

// When the server rejects 0-RTT, here because it restarted and can't read the
// client's session ticket any more, the queries sent as early data were
// discarded and have to be sent again once the handshake completes, on the
// same connection.
func TestDoQClient0RTTRejected(t *testing.T) {
	server := startDoQEarlyRecorder(t)

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	d, err := NewDoQClient("test-doq", server.addr, DoQClientOptions{TLSConfig: tlsClientConfig, Use0RTT: true})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Pick up a session ticket, and prove with a redial that the client
	// uses it for 0-RTT. Without that the query below would pass the same
	// way after a plain handshake.
	_, err = d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	server.closeCurrentConn(t)
	_, err = d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.True(t, server.last(t).early, "QUERY was not sent as 0-RTT; this test cannot prove anything about the rejection below")

	server.closeCurrentConn(t)
	server.restart(t)

	_, err = d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.False(t, server.last(t).early)
	require.Equal(t, int32(1), server.accepted.Load(), "the rejected connection was replaced instead of kept")
}

// A query that times out must tell the server it gave up (RFC 9250 4.3), so
// the server can drop it and free its stream.
func TestDoQClientCancelsTimedOutQuery(t *testing.T) {
	server := startDoQEarlyRecorder(t)

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	d, err := NewDoQClient("test-doq", server.addr, DoQClientOptions{TLSConfig: tlsClientConfig, QueryTimeout: 300 * time.Millisecond})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion(doqHangName, dns.TypeA)
	_, err = d.Resolve(q, ClientInfo{})
	require.Error(t, err)

	select {
	case cause := <-server.hangEnded:
		var streamErr *quic.StreamError
		require.ErrorAs(t, cause, &streamErr)
		require.True(t, streamErr.Remote)
		require.Equal(t, quic.StreamErrorCode(DOQRequestCancelled), streamErr.ErrorCode)
	case <-time.After(2 * time.Second):
		t.Fatal("the server's stream for the timed-out query is still open")
	}
}

// Only the last doqMaxReplaced replaced connections are left open.
func TestDOQReplacedLimit(t *testing.T) {
	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	d, err := NewDoQClient("test-doq-replaced", startTestDoQListener(t, new(TestResolver)), DoQClientOptions{TLSConfig: tlsConfig, QueryTimeout: time.Minute})
	require.NoError(t, err)
	ctx := context.Background()
	rAddr, err := resolveUDPAddr(ctx, d.endpoint, nil)
	require.NoError(t, err)

	first, err := d.connection.connection(ctx, rAddr, nil, d.log)
	require.NoError(t, err)
	stale := first
	for range doqMaxReplaced {
		stale, err = d.connection.connection(ctx, rAddr, stale, d.log)
		require.NoError(t, err)
	}
	require.NoError(t, first.Context().Err())
	_, err = d.connection.connection(ctx, rAddr, stale, d.log)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return first.Context().Err() != nil }, time.Second, 10*time.Millisecond)
}
