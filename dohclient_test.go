package rdns

import (
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestDoHClientSimplePOST(t *testing.T) {
	d, err := NewDoHClient("test-doh", "https://1.1.1.1/dns-query{?dns}", DoHClientOptions{Method: "POST"})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDoHClientSimpleGET(t *testing.T) {
	d, err := NewDoHClient("test-doh", "https://cloudflare-dns.com/dns-query{?dns}", DoHClientOptions{Method: "GET"})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDoHTcpTransportIdleTimeoutDefault(t *testing.T) {
	tr, err := dohTcpTransport(DoHClientOptions{})
	require.NoError(t, err)
	httpTransport := tr.(*http.Transport)
	require.Equal(t, defaultDoHIdleTimeout, httpTransport.IdleConnTimeout)
}

func TestDoHTcpTransportIdleTimeoutConfigured(t *testing.T) {
	tr, err := dohTcpTransport(DoHClientOptions{IdleTimeout: 2 * time.Minute})
	require.NoError(t, err)
	httpTransport := tr.(*http.Transport)
	require.Equal(t, 2*time.Minute, httpTransport.IdleConnTimeout)
}

func TestDoHQuicTransportIdleTimeoutDefault(t *testing.T) {
	tr, err := dohQuicTransport("https://example.com/dns-query", DoHClientOptions{})
	require.NoError(t, err)
	http3Transport := tr.(*http3.Transport)
	// When not configured, MaxIdleTimeout should not be set (zero value)
	// The quic-go library will use its own default
	require.Equal(t, time.Duration(0), http3Transport.QUICConfig.MaxIdleTimeout)
}

func TestDoHQuicTransportIdleTimeoutConfigured(t *testing.T) {
	tr, err := dohQuicTransport("https://example.com/dns-query", DoHClientOptions{IdleTimeout: 2 * time.Minute})
	require.NoError(t, err)
	http3Transport := tr.(*http3.Transport)
	require.Equal(t, 2*time.Minute, http3Transport.QUICConfig.MaxIdleTimeout)
}

func TestDoHClientIdleTimeoutNegative(t *testing.T) {
	_, err := NewDoHClient("test-doh", "https://example.com/dns-query", DoHClientOptions{IdleTimeout: -1 * time.Second})
	require.Error(t, err)
	require.Contains(t, err.Error(), "idle-timeout must not be negative")
}
