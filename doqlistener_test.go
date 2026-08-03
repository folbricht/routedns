package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// TestDoQListenerStartStop verifies that Stop() unblocks Start(). This guards
// two bugs: the value-receiver bug (where the listener bound in Start() was
// invisible to Stop()) and the Accept loop spinning on ErrServerClosed after
// the listener is closed. Either one leaves Start() running forever.
func TestDoQListenerStartStop(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getUDPLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)

	stopped := make(chan error, 1)
	go func() { stopped <- s.Start() }()

	// Give the listener a moment to bind and start accepting.
	time.Sleep(500 * time.Millisecond)

	require.NoError(t, s.Stop())

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Start did not return after Stop; listener is spinning on Accept")
	}
}

// TestDoQListenerStopRaceDuringStart calls Stop() concurrently with Start()
// binding the socket (the scenario the netns supervisor creates). It must be
// race-free under -race (s.ln is written by Start and read by Stop) and Start()
// must return. No queries are sent, so TestResolver is not touched.
func TestDoQListenerStopRaceDuringStart(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getUDPLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)

	stopped := make(chan error, 1)
	go func() { stopped <- s.Start() }()

	// Hammer Stop() (racing Start's bind) and retry until Start returns; Stop
	// is a no-op until the listener is published.
	deadline := time.After(5 * time.Second)
	for {
		_ = s.Stop()
		select {
		case err := <-stopped:
			require.NoError(t, err)
			return
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			require.FailNow(t, "Start did not return while Stop was retried")
		}
	}
}

// TestDoQListener0RTTBlocksNonReplayableOpcode is the regression test for the
// RFC 9250 4.5 violation reported in #599: a DNS UPDATE sent as 0-RTT data was
// forwarded to the upstream resolver, putting a state-changing transaction on a
// replayable transport.
//
// The client here is cut off from the server as soon as the server replies, so
// its handshake can never complete. That is the shape of a replayed first
// flight: an attacker can resend captured 0-RTT packets but cannot produce the
// handshake that follows. Nothing non-replayable may reach the resolver.
//
// A QUERY is sent on the same connection, written *before* the UPDATE, as a
// control. Since the relay's cutoff is one-way, the QUERY arriving proves the
// earlier UPDATE datagram was delivered too. Without that control the test
// would pass just as happily if the relay had cut the connection off early and
// the server had never seen anything at all.
func TestDoQListener0RTTBlocksNonReplayableOpcode(t *testing.T) {
	var (
		mu      sync.Mutex
		opcodes []int
	)
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			mu.Lock()
			opcodes = append(opcodes, q.Opcode)
			mu.Unlock()
			a := new(dns.Msg)
			a.SetReply(q)
			return a, nil
		},
	}
	seen := func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), opcodes...)
	}

	addr, err := getUDPLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() { _ = s.Start() }()
	defer s.Stop()
	time.Sleep(500 * time.Millisecond)

	relay := newEarlyDataRelay(t, addr)
	tlsClientConfig := doqTestClientConfig(t)
	quicConfig := &quic.Config{Allow0RTT: true}

	// Warm-up connection: complete a handshake and collect a session ticket.
	warmup, err := quic.DialAddrEarly(context.Background(), relay.addr, tlsClientConfig, quicConfig)
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	writeDoQQuery(t, warmup, q)
	require.Eventually(t, func() bool { return len(seen()) == 1 }, 5*time.Second, 20*time.Millisecond)
	warmup.CloseWithError(0, "")

	mu.Lock()
	opcodes = nil
	mu.Unlock()

	// Resume. Everything written now goes out as 0-RTT data.
	relay.armCutoff()
	resumed, err := quic.DialAddrEarly(context.Background(), relay.addr, tlsClientConfig, quicConfig)
	require.NoError(t, err)
	defer resumed.CloseWithError(0, "")

	update := new(dns.Msg)
	update.SetUpdate("replay.lab.")
	rr, err := dns.NewRR(`early.replay.lab. 60 IN TXT "doq-0rtt-update"`)
	require.NoError(t, err)
	update.Insert([]dns.RR{rr})
	writeDoQQuery(t, resumed, update)
	writeDoQQuery(t, resumed, q)

	// The control must arrive, otherwise the rest of the test proves nothing.
	require.Eventually(t, func() bool {
		for _, o := range seen() {
			if o == dns.OpcodeQuery {
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "0-RTT QUERY never reached the resolver; the relay cut the connection off too early and this test is inconclusive")

	require.Positive(t, relay.dropped.Load(), "cutoff never engaged; the client could still complete its handshake")

	// Give a late UPDATE every chance to show up before declaring it blocked.
	time.Sleep(time.Second)
	require.NotContains(t, seen(), dns.OpcodeUpdate, "UPDATE received as 0-RTT was forwarded upstream")
}

// TestDoQListener0RTTAllowsNonReplayableOpcodeAfterHandshake covers the other
// half of the rule: an UPDATE in 0-RTT is held, not refused. A well-behaved
// client completes its handshake a moment later, and the transaction then
// proceeds normally.
func TestDoQListener0RTTAllowsNonReplayableOpcodeAfterHandshake(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getUDPLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() { _ = s.Start() }()
	defer s.Stop()
	time.Sleep(500 * time.Millisecond)

	tlsClientConfig := doqTestClientConfig(t)
	quicConfig := &quic.Config{Allow0RTT: true}

	warmup, err := quic.DialAddrEarly(context.Background(), addr, tlsClientConfig, quicConfig)
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	writeDoQQuery(t, warmup, q)
	require.Eventually(t, func() bool { return upstream.HitCount() == 1 }, 5*time.Second, 20*time.Millisecond)
	warmup.CloseWithError(0, "")

	resumed, err := quic.DialAddrEarly(context.Background(), addr, tlsClientConfig, quicConfig)
	require.NoError(t, err)
	defer resumed.CloseWithError(0, "")

	update := new(dns.Msg)
	update.SetUpdate("replay.lab.")
	rr, err := dns.NewRR(`early.replay.lab. 60 IN TXT "doq-0rtt-update"`)
	require.NoError(t, err)
	update.Insert([]dns.RR{rr})
	writeDoQQuery(t, resumed, update)

	require.Eventually(t, func() bool { return upstream.HitCount() == 2 }, 5*time.Second, 20*time.Millisecond,
		"UPDATE was dropped instead of being held until the handshake completed")
}

func doqTestClientConfig(t *testing.T) *tls.Config {
	t.Helper()
	c, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	c.NextProtos = []string{"doq"}
	c.ServerName = "localhost"
	c.ClientSessionCache = tls.NewLRUClientSessionCache(10)
	return c
}

// writeDoQQuery opens a stream and writes a length-prefixed DNS message. It
// does not wait for the response; these tests observe the upstream resolver
// instead, since a connection whose handshake never completes cannot be read
// from reliably.
func writeDoQQuery(t *testing.T, connection *quic.Conn, m *dns.Msg) {
	t.Helper()
	stream, err := connection.OpenStreamSync(context.Background())
	require.NoError(t, err)
	p, err := m.Pack()
	require.NoError(t, err)
	out := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(out, uint16(len(p)))
	copy(out[2:], p)
	_, err = stream.Write(out)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
}

// earlyDataRelay is a UDP proxy that can silence the client. Once armed, the
// first datagram the server sends triggers a cutoff, after which no further
// client datagram is forwarded. The client's handshake can then never complete,
// so anything the server acts on came from the replayable 0-RTT first flight.
type earlyDataRelay struct {
	addr     string
	upstream *net.UDPAddr
	conn     *net.UDPConn
	client   atomic.Pointer[net.UDPAddr]
	armed    atomic.Bool
	cutoff   atomic.Bool
	dropped  atomic.Int32
}

func newEarlyDataRelay(t *testing.T, upstreamAddr string) *earlyDataRelay {
	t.Helper()
	upstream, err := net.ResolveUDPAddr("udp", upstreamAddr)
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	r := &earlyDataRelay{addr: conn.LocalAddr().String(), upstream: upstream, conn: conn}
	t.Cleanup(func() { conn.Close() })
	go r.run()
	return r
}

func (r *earlyDataRelay) armCutoff() { r.armed.Store(true) }

func (r *earlyDataRelay) run() {
	var (
		toServer *net.UDPConn
		once     sync.Once
	)
	buf := make([]byte, 2048)
	for {
		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.client.Store(addr)
		once.Do(func() {
			toServer, err = net.DialUDP("udp", nil, r.upstream)
			if err != nil {
				return
			}
			go func() {
				b := make([]byte, 2048)
				for {
					n, err := toServer.Read(b)
					if err != nil {
						return
					}
					if r.armed.Load() {
						r.cutoff.Store(true)
					}
					if client := r.client.Load(); client != nil {
						r.conn.WriteToUDP(b[:n], client)
					}
				}
			}()
		})
		if toServer == nil {
			return
		}
		if r.cutoff.Load() {
			r.dropped.Add(1)
			continue
		}
		if _, err := toServer.Write(buf[:n]); err != nil {
			return
		}
	}
}
