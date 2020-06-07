package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoTClientSimple(t *testing.T) {
	d, _ := NewDoTClient("test-dot", "dns.google:853", DoTClientOptions{})
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDoTClientCA(t *testing.T) {
	// Create client cert options with a CA. TODO: Should read the cert dynamically
	// to avoid failure when this expires or changes.
	tlsConfig, err := TLSClientConfig("testdata/DigiCertECCSecureServerCA.pem", "", "")
	require.NoError(t, err)

	// DoT client with valid CA
	d, _ := NewDoTClient("test-dot", "1.1.1.1:853", DoTClientOptions{TLSConfig: tlsConfig})
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)

	// DoT client with invalid CA
	d, _ = NewDoTClient("test-dot", "dns.google:853", DoTClientOptions{TLSConfig: tlsConfig})
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = d.Resolve(q, ClientInfo{})
	require.Error(t, err)
}
