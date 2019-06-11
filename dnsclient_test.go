package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSClientSimpleTCP(t *testing.T) {
	d := NewDNSClient("8.8.8.8:53", "tcp")
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDNSClientSimpleUDP(t *testing.T) {
	d := NewDNSClient("8.8.8.8:53", "udp")
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}
