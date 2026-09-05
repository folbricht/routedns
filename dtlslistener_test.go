package rdns

import (
	"net"
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
//
// The listener is stopped without waiting here. Shutdown blocks after a
// handshake the peer abandoned, because dns.Server.Shutdown waits on the
// connection pion left behind. That is a pre-existing issue in the DTLS
// listener, unrelated to pre-shared keys: the same happens with certificates,
// and it does not affect the successful path above.
func TestDTLSListenerPSKMismatch(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getLnAddress()
	require.NoError(t, err)

	serverConfig, err := DTLSServerConfig("", "", "", false, &PSK{Key: []byte{0x01, 0x02, 0x03, 0x04}, Identity: "test-server"})
	require.NoError(t, err)
	s := NewDTLSListener("test-dtls-psk-mismatch", addr, DTLSListenerOptions{DTLSConfig: serverConfig}, upstream)
	go s.Start()
	defer func() { go s.Stop() }()
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

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ln, err := dtls.Listen("udp", addr, serverConfig)
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

	conn, err := dtls.Dial("udp", ln.Addr().(*net.UDPAddr), clientConfig)
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
