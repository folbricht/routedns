package rdns

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNetDialer(t *testing.T) {
	r, _ := NewDNSClient("test-dns", "8.8.8.8:53", "udp", DNSClientOptions{})
	dialer := NewNetDialer(r)
	c, err := dialer.DialContext(context.Background(), "tcp", "one.one.one.one:53")
	require.NoError(t, err)
	c.Close()
}

func TestNetResolver(t *testing.T) {
	r, _ := NewDNSClient("test-dns", "8.8.8.8:53", "udp", DNSClientOptions{})
	netResolver := NewNetResolver(r)
	addr, err := netResolver.LookupHost(context.Background(), "one.one.one.one")
	require.NoError(t, err)
	require.Contains(t, addr, "1.1.1.1")
}
