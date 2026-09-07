package rdns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/pion/dtls/v3"
	"github.com/stretchr/testify/require"
)

func TestDTLSListener(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener
	dtlsConfig, err := DTLSServerConfig("", "testdata/server.crt", "testdata/server.key", false, nil)
	require.NoError(t, err)
	s := NewDTLSListener("test-dtls-server", addr, DTLSListenerOptions{DTLSConfig: dtlsConfig}, upstream)
	go s.Start()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener
	dtlsClientConfig, err := DTLSClientConfig("testdata/ca.crt", "", "", nil)
	require.NoError(t, err)
	c, err := NewDTLSClient("test-dtls-client", addr, DTLSClientOptions{DTLSConfig: dtlsClientConfig})
	require.NoError(t, err)

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())
}

// A PSK handshake end-to-end, with no certificates on either side.
func TestDTLSListenerPSK(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	upstream := new(TestResolver)

	addr, err := getLnAddress()
	require.NoError(t, err)

	serverConfig, err := DTLSServerConfig("", "", "", false, &PSK{Key: key, Identity: "test-server"})
	require.NoError(t, err)
	s := NewDTLSListener("test-dtls-psk-server", addr, DTLSListenerOptions{DTLSConfig: serverConfig}, upstream)
	go s.Start()
	defer s.Stop()
	time.Sleep(time.Second)

	clientConfig, err := DTLSClientConfig("", "", "", &PSK{Key: key, Identity: "test-client"})
	require.NoError(t, err)
	c, err := NewDTLSClient("test-dtls-psk-client", addr, DTLSClientOptions{DTLSConfig: clientConfig})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, 1, upstream.HitCount())
}

// The key has to be verified, not just accepted, so a client with the wrong
// one must not get an answer through.
func TestDTLSListenerPSKMismatch(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getLnAddress()
	require.NoError(t, err)

	serverConfig, err := DTLSServerConfig("", "", "", false, &PSK{Key: []byte{0x01, 0x02, 0x03, 0x04}, Identity: "test-server"})
	require.NoError(t, err)
	s := NewDTLSListener("test-dtls-psk-mismatch", addr, DTLSListenerOptions{DTLSConfig: serverConfig}, upstream)
	go s.Start()
	defer s.Stop()
	time.Sleep(time.Second)

	clientConfig, err := DTLSClientConfig("", "", "", &PSK{Key: []byte{0xff, 0xfe, 0xfd, 0xfc}, Identity: "test-client"})
	require.NoError(t, err)
	c, err := NewDTLSClient("test-dtls-psk-mismatch-client", addr, DTLSClientOptions{DTLSConfig: clientConfig, QueryTimeout: time.Second})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.Error(t, err, "a query must not succeed with the wrong key")
	require.Equal(t, 0, upstream.HitCount(), "the query must not reach the upstream")
}

// A client PSK without an identity is rejected up front, since pion fails the
// dial with the same requirement.
func TestDTLSClientPSKRequiresIdentity(t *testing.T) {
	_, err := DTLSClientConfig("", "", "", &PSK{Key: []byte{0x01}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "psk-identity is required")
}

// Certificates and a PSK are alternatives, not a combination. A half-specified
// certificate counts too: checking the loaded certificates rather than the file
// names would let one through and silently drop it.
func TestDTLSPSKAndCertificateRejected(t *testing.T) {
	for _, tc := range []struct{ name, crt, key string }{
		{"both", "testdata/server.crt", "testdata/server.key"},
		{"certificate only", "testdata/server.crt", ""},
		{"key only", "", "testdata/server.key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DTLSServerConfig("", tc.crt, tc.key, false, &PSK{Key: []byte{0x01}})
			require.Error(t, err)
			require.Contains(t, err.Error(), "cannot be combined with a certificate")

			_, err = DTLSClientConfig("", tc.crt, tc.key, &PSK{Key: []byte{0x01}, Identity: "client"})
			require.Error(t, err)
			require.Contains(t, err.Error(), "cannot be combined with a certificate")
		})
	}
}

// mutual-tls asks the client for a certificate, which a PSK handshake never
// sends. Without this the listener starts and then fails every handshake.
func TestDTLSPSKAndMutualTLSRejected(t *testing.T) {
	_, err := DTLSServerConfig("testdata/ca.crt", "", "", true, &PSK{Key: []byte{0x01}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot be combined with mutual-tls")
}

// Two peers both using the configs built here have to end up on the forward
// secret suite. A server selects the first entry of the client's list that it
// also supports, so this depends on the order of pskCipherSuites and would
// silently regress if the AEAD suites were moved to the front.
func TestDTLSPSKNegotiatesForwardSecrecy(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	serverConfig, err := DTLSServerConfig("", "", "", false, &PSK{Key: key, Identity: "server"})
	require.NoError(t, err)
	clientConfig, err := DTLSClientConfig("", "", "", &PSK{Key: key, Identity: "client"})
	require.NoError(t, err)

	// Driven through the options API rather than the deprecated dtls.Listen,
	// but from the configs built above, so the suite list under test is still
	// the one this package produces.
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ln, err := dtls.ListenWithOptions("udp", addr,
		dtls.WithPSK(serverConfig.PSK),
		dtls.WithPSKIdentityHint(serverConfig.PSKIdentityHint),
		dtls.WithCipherSuites(serverConfig.CipherSuites...),
	)
	require.NoError(t, err)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		_, _ = conn.Read(buf) // completes the handshake on this side
	}()

	conn, err := dtls.DialWithOptions("udp", ln.Addr().(*net.UDPAddr),
		dtls.WithPSK(clientConfig.PSK),
		dtls.WithPSKIdentityHint(clientConfig.PSKIdentityHint),
		dtls.WithCipherSuites(clientConfig.CipherSuites...),
	)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	<-done

	state, ok := conn.ConnectionState()
	require.True(t, ok)
	require.Equal(t, dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, state.CipherSuiteID,
		"a PSK connection between two RouteDNS peers should use the forward secret suite")
}

// A peer that starts a handshake and then stops responding must not pin the
// listener open. pion runs the handshake on the first Read with an unbounded
// context, so without a deadline of our own the connection goroutine never
// returns and dns.Server.Shutdown waits on it forever.
func TestDTLSListenerStopAfterAbandonedHandshake(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getLnAddress()
	require.NoError(t, err)

	serverConfig, err := DTLSServerConfig("", "testdata/server.crt", "testdata/server.key", false, nil)
	require.NoError(t, err)
	s := NewDTLSListener("test-dtls-abandoned", addr, DTLSListenerOptions{DTLSConfig: serverConfig}, upstream)
	go s.Start()
	time.Sleep(time.Second)

	// Send a ClientHello and then go away. The server accepts the connection
	// and starts a handshake that never completes.
	conn, err := net.Dial("udp", addr)
	require.NoError(t, err)
	clientHello := []byte{
		0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0xfe, 0xfd, 0x00, 0x00,
	}
	_, err = conn.Write(clientHello)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	time.Sleep(500 * time.Millisecond)

	// Shutdown has to cancel the handshake rather than wait it out, so this is
	// deliberately far below dtlsHandshakeTimeout.
	stopped := make(chan error, 1)
	start := time.Now()
	go func() { stopped <- s.Stop() }()
	select {
	case <-stopped:
	case <-time.After(dtlsHandshakeTimeout / 2):
		t.Fatal("Stop blocked on a connection whose handshake was abandoned")
	}
	require.Less(t, time.Since(start), dtlsHandshakeTimeout/2,
		"shutdown waited out the handshake timeout instead of cancelling it")
}

// stalledHandshakeConn stands in for a *dtls.Conn whose peer never finishes the
// handshake: HandshakeContext returns only when the context is done.
type stalledHandshakeConn struct {
	net.Conn
	calls atomic.Int64
}

func (c *stalledHandshakeConn) HandshakeContext(ctx context.Context) error {
	c.calls.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

func (c *stalledHandshakeConn) Read([]byte) (int, error)  { panic("handshake should not complete") }
func (c *stalledHandshakeConn) Write([]byte) (int, error) { panic("handshake should not complete") }

// Read and Write both wait for the handshake, so both have to give up when it
// does not finish, and between them they must only run it once.
func TestDTLSConnHandshakeDeadline(t *testing.T) {
	stalled := &stalledHandshakeConn{}
	c := newDTLSConn(stalled)
	c.handshakeTimeout = time.Second

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = c.Read(make([]byte, 2))
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = c.Write([]byte("query"))
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Read and Write did not return after the handshake deadline")
	}

	require.ErrorIs(t, errs[0], context.DeadlineExceeded)
	require.ErrorIs(t, errs[1], context.DeadlineExceeded)
	require.Equal(t, int64(1), stalled.calls.Load(), "the handshake should run once for the connection")
}
