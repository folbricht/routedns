package rdns

import (
	"net"
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

func TestSelectLocalAddr(t *testing.T) {
	v4 := net.ParseIP("10.0.0.1")
	v6 := net.ParseIP("fd00::1")
	generic := net.ParseIP("192.168.1.1")

	tests := []struct {
		name     string
		target   string
		local    net.IP
		localV4  net.IP
		localV6  net.IP
		expected net.IP
	}{
		{"v4 target with v4 addr", "1.2.3.4:53", generic, v4, v6, v4},
		{"v6 target with v6 addr", "[2001:db8::1]:53", generic, v4, v6, v6},
		{"v4 target, only generic", "1.2.3.4:53", generic, nil, nil, generic},
		{"v6 target, only generic", "[2001:db8::1]:53", generic, nil, nil, generic},
		{"v4 target, no v4 specific", "1.2.3.4:53", generic, nil, v6, generic},
		{"v6 target, no v6 specific", "[2001:db8::1]:53", generic, v4, nil, generic},
		{"hostname target, all set", "example.com:53", generic, v4, v6, generic}, // selectLocalAddr doesn't resolve hostnames; callers must use resolveEndpointAddr first
		{"all nil", "1.2.3.4:53", nil, nil, nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectLocalAddr(tt.target, tt.local, tt.localV4, tt.localV6)
			if tt.expected == nil {
				require.Nil(t, result)
			} else {
				require.True(t, tt.expected.Equal(result), "expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResolveEndpointAddr(t *testing.T) {
	tests := []struct {
		name    string
		address string
		checkFn func(t *testing.T, result string)
	}{
		{
			"ip4 passthrough",
			"1.2.3.4:53",
			func(t *testing.T, result string) {
				require.Equal(t, "1.2.3.4:53", result)
			},
		},
		{
			"ip6 passthrough",
			"[2001:db8::1]:53",
			func(t *testing.T, result string) {
				require.Equal(t, "[2001:db8::1]:53", result)
			},
		},
		{
			"hostname resolved",
			"localhost:53",
			func(t *testing.T, result string) {
				host, port, err := net.SplitHostPort(result)
				require.NoError(t, err)
				require.Equal(t, "53", port)
				require.NotNil(t, net.ParseIP(host), "expected resolved IP, got %q", host)
			},
		},
		{
			"invalid address passthrough",
			"not-a-valid-address",
			func(t *testing.T, result string) {
				require.Equal(t, "not-a-valid-address", result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveEndpointAddr(tt.address)
			tt.checkFn(t, result)
		})
	}
}
