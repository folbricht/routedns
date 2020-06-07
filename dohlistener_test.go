package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoHListenerSimple(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s, err := NewDoHListener("test-doh", addr, DoHListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	require.NoError(t, err)
	go s.Start()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener using POST
	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "")
	require.NoError(t, err)
	u := "https://" + addr + "/dns-query"
	cPost, err := NewDoHClient("test-doh", u, DoHClientOptions{TLSConfig: tlsConfig, Method: "POST"})
	require.NoError(t, err)

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = cPost.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())

	// Make a client that uses GET
	u = "https://" + addr + "/dns-query{?dns}"
	cGet, err := NewDoHClient("test-doh", u, DoHClientOptions{TLSConfig: tlsConfig, Method: "GET"})
	require.NoError(t, err)

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	_, err = cGet.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 2, upstream.HitCount())
}

func TestDoHListenerMutual(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener, expecting client certs to be presented.
	tlsServerConfig, err := TLSServerConfig("testdata/ca.crt", "testdata/server.crt", "testdata/server.key", true)
	require.NoError(t, err)
	s, err := NewDoHListener("test-doh", addr, DoHListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	require.NoError(t, err)
	go s.Start()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener. Need to trust the issuer of the server certificate and
	// present a client certificate.
	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "testdata/client.crt", "testdata/client.key")
	require.NoError(t, err)
	u := "https://" + addr + "/dns-query"
	c, err := NewDoHClient("test-doh", u, DoHClientOptions{TLSConfig: tlsClientConfig})
	require.NoError(t, err)

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())
}

func TestDoHListenerMutualQUIC(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getUDPLnAddress()
	require.NoError(t, err)

	// Create the listener, expecting client certs to be presented.
	tlsServerConfig, err := TLSServerConfig("testdata/ca.crt", "testdata/server.crt", "testdata/server.key", true)
	require.NoError(t, err)
	s, err := NewDoHListener("test-doh", addr, DoHListenerOptions{TLSConfig: tlsServerConfig, Transport: "quic"}, upstream)
	require.NoError(t, err)
	go s.Start()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener. Need to trust the issuer of the server certificate and
	// present a client certificate.
	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "testdata/client.crt", "testdata/client.key")
	require.NoError(t, err)
	u := "https://" + addr + "/dns-query"
	c, err := NewDoHClient("test-doh", u, DoHClientOptions{TLSConfig: tlsClientConfig, Transport: "quic"})
	require.NoError(t, err)

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())
}
