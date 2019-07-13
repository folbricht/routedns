package rdns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoTListenerSimple(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewDoTListener(addr, DoTListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() {
		err := s.Start()
		require.NoError(t, err)
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener. Need to trust the issue of the server certificate.
	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "")
	require.NoError(t, err)
	c := NewDoTClient(addr, DoTClientOptions{TLSConfig: tlsConfig})

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())
}

func TestDoTListenerMutual(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener, expecting client certs to be presented.
	tlsServerConfig, err := TLSServerConfig("testdata/ca.crt", "testdata/server.crt", "testdata/server.key", true)
	require.NoError(t, err)
	s := NewDoTListener(addr, DoTListenerOptions{TLSConfig: tlsServerConfig}, upstream)

	go func() {
		err := s.Start()
		require.NoError(t, err)
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener. Need to trust the issue of the server certificate and
	// present a client certificate.
	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "testdata/client.crt", "testdata/client.key")
	require.NoError(t, err)
	c := NewDoTClient(addr, DoTClientOptions{TLSConfig: tlsClientConfig})

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())
}

func getLnAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil
	}
	defer l.Close()
	return l.Addr().String(), nil
}
