package rdns

import (
	"crypto/tls"
	"encoding/pem"
	"os"
	"path/filepath"
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
	// Read the server certificate from the public server write it to a temp file
	conn, err := tls.Dial("tcp", "1.1.1.1:853", nil)
	require.NoError(t, err)
	state := conn.ConnectionState()
	crt := state.PeerCertificates[0]
	crtEncoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
	crtFile := filepath.Join(t.TempDir(), "certificate.pem")
	err = os.WriteFile(crtFile, crtEncoded, 0644)
	require.NoError(t, err)
	conn.Close()

	// Create a config with CA using the temp file
	tlsConfig, err := TLSClientConfig(crtFile, "", "")
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
