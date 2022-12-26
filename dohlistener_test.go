package rdns

import (
	"net"
	"net/http"
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
	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
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

	// The listener should not use X-Forwarded-For if HTTPProxyNet is not set.
	require.Nil(t, s.opt.HTTPProxyNet)
	r, _ := http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Add("X-Forwarded-For", "10.0.1.3")
	client := s.extractClientAddress(r)
	require.Equal(t, "10.0.0.2", client.String())
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
	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "testdata/client.crt", "testdata/client.key", "")
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
	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "testdata/client.crt", "testdata/client.key", "")
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

func TestClientBehindProxy(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	expectedProxyAddr := "10.0.0.2"
	expectedProxyNet := "10.0.0.2/32"
	_, proxyNet, err := net.ParseCIDR(expectedProxyNet)
	require.NoError(t, err)
	s, err := NewDoHListener("test-doh", addr, DoHListenerOptions{TLSConfig: tlsServerConfig, HTTPProxyNet: proxyNet}, upstream)
	require.NoError(t, err)

	// Verify that the ProxyNet has been set.
	require.Equal(t, expectedProxyNet, s.opt.HTTPProxyNet.String())

	// There is no proxy.
	r, _ := http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "192.168.1.2:1234"
	client := s.extractClientAddress(r)
	require.Equal(t, "192.168.1.2", client.String())

	// The client is our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	client = s.extractClientAddress(r)
	require.Equal(t, expectedProxyAddr, client.String())

	// The client is running on and behind our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Add("X-Forwarded-For", "127.0.0.1")
	client = s.extractClientAddress(r)
	require.Equal(t, expectedProxyAddr, client.String())

	// The IPv6 client is running on and behind our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Add("X-Forwarded-For", "::1")
	client = s.extractClientAddress(r)
	require.Equal(t, expectedProxyAddr, client.String())

	// The client is behind our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Add("X-Forwarded-For", "10.0.1.5")
	client = s.extractClientAddress(r)
	require.Equal(t, "10.0.1.5", client.String())

	// X-Forwarded-For is invalid.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Add("X-Forwarded-For", "my-other-computer")
	client = s.extractClientAddress(r)
	require.Equal(t, expectedProxyAddr, client.String())

	// The IPv6 client behind our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Add("X-Forwarded-For", "2001:4860:4860::8")
	client = s.extractClientAddress(r)
	require.Equal(t, "2001:4860:4860::8", client.String())

	// The client is behind an untrusted proxy (10.0.1.6) behind our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Add("X-Forwarded-For", "192.168.1.2, 10.0.1.6")
	client = s.extractClientAddress(r)
	require.Equal(t, "10.0.1.6", client.String())

	// Our proxy is behind an untrusted proxy (10.0.1.6), ignore XFF.
	// In the future we might parse XFF to determine the client is 192.168.1.2.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "10.0.1.6:1234"
	r.Header.Add("X-Forwarded-For", "192.168.1.2, 10.0.0.2")
	client = s.extractClientAddress(r)
	require.Equal(t, "10.0.1.6", client.String())
}

func TestIPv6Proxy(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	expectedProxyAddr := "2001:4860:4860::8"
	expectedProxyNet := "2001:4860:4860::8/128"
	_, proxyNet, err := net.ParseCIDR(expectedProxyNet)
	require.NoError(t, err)
	s, err := NewDoHListener("test-doh", addr, DoHListenerOptions{TLSConfig: tlsServerConfig, HTTPProxyNet: proxyNet}, upstream)
	require.NoError(t, err)

	// Verify that the ProxyNet has been set.
	require.Equal(t, expectedProxyNet, s.opt.HTTPProxyNet.String())

	// There is no proxy.
	r, _ := http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "[2001:4860:4860::1]:1234"
	client := s.extractClientAddress(r)
	require.Equal(t, "2001:4860:4860::1", client.String())

	// The client is our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "[2001:4860:4860::8]:1234"
	client = s.extractClientAddress(r)
	require.Equal(t, expectedProxyAddr, client.String())

	// The client is behind our proxy.
	r, _ = http.NewRequest("GET", "https://www.example.com", nil)
	r.RemoteAddr = "[2001:4860:4860::8]:1234"
	r.Header.Add("X-Forwarded-For", "10.0.1.5")
	client = s.extractClientAddress(r)
	require.Equal(t, net.IPv4(10, 0, 1, 5), client)
}
