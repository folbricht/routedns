package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoTClientSimple(t *testing.T) {
	d, err := NewDoTClient("dns.google:853", DoTClientOptions{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDoTClientCA(t *testing.T) {
	// Create client cert options with a CA. TODO: Should read the cert dynamically
	// to avoid failure when this expires or changes.
	opt := DoTClientOptions{}
	opt.CAFile = "testdata/DigiCertECCSecureServerCA.pem"

	// DoT client with valid CA
	d, err := NewDoTClient("1.1.1.1:853", opt)
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)

	// DoT client with invalid CA
	d, err = NewDoTClient("dns.google:853", opt)
	require.NoError(t, err)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = d.Resolve(q, ClientInfo{})
	require.Error(t, err)
}
