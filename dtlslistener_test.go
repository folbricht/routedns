package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
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

// Certificates and a PSK are alternatives, not a combination.
func TestDTLSPSKAndCertificateRejected(t *testing.T) {
	_, err := DTLSServerConfig("", "testdata/server.crt", "testdata/server.key", false, &PSK{Key: []byte{0x01}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot be combined with a certificate")
}
