package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSClientSimpleTCP(t *testing.T) {
	d, _ := NewDNSClient("test-dns", "8.8.8.8:53", "tcp", DNSClientOptions{})
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDNSClientSimpleUDP(t *testing.T) {
	d, _ := NewDNSClient("test-dns", "8.8.8.8:53", "udp", DNSClientOptions{})
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}
