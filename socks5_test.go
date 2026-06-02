package rdns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startMinimalSocks5Proxy starts a no-auth SOCKS5 CONNECT proxy that relays to
// the requested target. It supports IPv4 and domain destination address types,
// which is all the socks5 client emits here.
func startMinimalSocks5Proxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSocks5Connect(c)
		}
	}()
	return ln.Addr().String()
}

func serveSocks5Connect(c net.Conn) {
	defer c.Close()

	// Negotiation: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	// Reply: no authentication required.
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[1] != 0x01 { // CONNECT only
		return
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(pb)))

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	defer upstream.Close()

	// Reply: success, bound address 0.0.0.0:0.
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	go io.Copy(upstream, c)
	io.Copy(c, upstream)
}

// startEchoTCPServer starts a TCP server that echoes back whatever it reads.
func startEchoTCPServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

// TestSocks5DialerLocalAddr verifies that a Socks5Dialer configured with a local
// address dials successfully and binds the connection to the proxy to that
// source IP. Without binding a port to the local IP, the underlying socks5
// library rejects the bare IP with "missing port in address".
func TestSocks5DialerLocalAddr(t *testing.T) {
	echo := startEchoTCPServer(t)
	proxyAddr := startMinimalSocks5Proxy(t)

	d := NewSocks5Dialer(proxyAddr, Socks5DialerOptions{
		TCPTimeout: 2 * time.Second,
		UDPTimeout: 2 * time.Second,
		LocalAddr:  net.ParseIP("127.0.0.1"),
	})

	conn, err := d.Dial("tcp", echo.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// The connection to the proxy should be bound to the configured local IP.
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host, "connection should be bound to the configured source IP")

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
}

// TestSocks5SockOptsDialHooks verifies that socket options on a Socks5Dialer
// install per-client dial hooks (applied at socket creation; the proxy conn
// doesn't expose its descriptor for post-connect application), and that no
// hooks are installed without them.
func TestSocks5SockOptsDialHooks(t *testing.T) {
	d := NewSocks5Dialer("127.0.0.1:1080", Socks5DialerOptions{})
	assert.Nil(t, d.Client.DialTCP)
	assert.Nil(t, d.Client.DialUDP)

	d = NewSocks5Dialer("127.0.0.1:1080", Socks5DialerOptions{
		SocketOptions: SocketOptions{FWMark: 1},
	})
	assert.NotNil(t, d.Client.DialTCP)
	assert.NotNil(t, d.Client.DialUDP)
}

// TestSocks5SockOptsDialer exercises the dial hook itself, including local
// address binding. Socket options requiring privileges (fwmark, bind-if) can't
// be set in an unprivileged test, so this covers the dial/bind mechanics.
func TestSocks5SockOptsDialer(t *testing.T) {
	echo := startEchoTCPServer(t)
	dial := socks5SockOptsDialer(SocketOptions{}, 2*time.Second)

	for _, laddr := range []string{"", "127.0.0.1:0"} {
		conn, err := dial("tcp", laddr, echo.Addr().String())
		require.NoError(t, err, "laddr %q", laddr)
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		buf := make([]byte, 4)
		_, err = io.ReadFull(conn, buf)
		require.NoError(t, err)
		assert.Equal(t, "ping", string(buf))
		conn.Close()
	}
}

func TestSocks5LocalIP(t *testing.T) {
	tests := []struct {
		in   string
		want string // "" means nil
	}{
		{"", ""},
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:0", "1.2.3.4"},
		{"1.2.3.4:5353", "1.2.3.4"},
		{"[::1]:53", "::1"},
		{"::1", "::1"},
		{"bogus", ""},
	}
	for _, tc := range tests {
		got := socks5LocalIP(tc.in)
		if tc.want == "" {
			assert.Nil(t, got, "socks5LocalIP(%q)", tc.in)
			continue
		}
		require.NotNil(t, got, "socks5LocalIP(%q)", tc.in)
		assert.True(t, got.Equal(net.ParseIP(tc.want)), "socks5LocalIP(%q) = %v, want %s", tc.in, got, tc.want)
	}
}
