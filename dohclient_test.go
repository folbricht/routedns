package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoHClientSimplePOST(t *testing.T) {
	d, err := NewDoHClient("https://1.1.1.1/dns-query{?dns}", DoHClientOptions{Method: "POST"})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q)
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDoHClientSimpleGET(t *testing.T) {
	d, err := NewDoHClient("https://cloudflare-dns.com/dns-query{?dns}", DoHClientOptions{Method: "GET"})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q)
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}
