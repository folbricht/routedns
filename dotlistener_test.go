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

	s := NewDoTListener("test-ln", addr, "", DoTListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() {
		err := s.Start()
		require.NoError(t, err)
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener. Need to trust the issue of the server certificate.
	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	c, _ := NewDoTClient("test-dot", addr, DoTClientOptions{TLSConfig: tlsConfig})

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
	s := NewDoTListener("test-ln", addr, "", DoTListenerOptions{TLSConfig: tlsServerConfig}, upstream)

	go func() {
		err := s.Start()
		require.NoError(t, err)
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener. Need to trust the issue of the server certificate and
	// present a client certificate.
	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "testdata/client.crt", "testdata/client.key", "")
	require.NoError(t, err)
	c, _ := NewDoTClient("test-dot", addr, DoTClientOptions{TLSConfig: tlsClientConfig})

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())
}

func TestDoTListenerPadding(t *testing.T) {
	// Define a listener that does not respond with padding
	upstream, _ := NewDNSClient("test-dns", "8.8.8.8:53", "udp", DNSClientOptions{})

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewDoTListener("test-ln", addr, "", DoTListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() {
		err := s.Start()
		require.NoError(t, err)
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener. Need to trust the issue of the server certificate.
	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	c, _ := NewDoTClient("test-dot", addr, DoTClientOptions{TLSConfig: tlsConfig})

	// Send a query with the EDNS0 option set. This should cause the listener to add padding in the response.
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	q.SetEdns0(4096, false)
	a, err := c.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	edns0 := a.IsEdns0()
	require.NotNil(t, edns0, "expected EDNS0 option in response")
	var foundPadding bool
	for _, opt := range edns0.Option {
		if opt.Option() == dns.EDNS0PADDING {
			foundPadding = true
		}
	}
	require.True(t, foundPadding, "expected padding in response")

	// Send a query without the EDNS0 option. The response should not have an EDNS0 record.
	q = new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	a, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	edns0 = a.IsEdns0()
	require.Nil(t, edns0, "unexpected EDNS0 option in response")
}

func getLnAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func getUDPLnAddress() (string, error) {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.LocalAddr().String(), nil
}
