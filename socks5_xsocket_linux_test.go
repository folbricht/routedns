//go:build linux

package rdns

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// startCountingXSocketServer is like startFakeXSocketServer but increments
// *count for every fd request it serves, so a test can assert that a connection
// was actually obtained via the xsocket-server rather than the default dialer.
func startCountingXSocketServer(t *testing.T, count *int64) string {
	t.Helper()
	name := fmt.Sprintf("@rdns-socks5-xsocket-test-%d-%d", os.Getpid(), atomic.AddUint64(&xsocketTestSeq, 1))

	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err, "server socket")
	if err := unix.Bind(lfd, &unix.SockaddrUnix{Name: name}); err != nil {
		unix.Close(lfd)
		t.Fatalf("server bind: %v", err)
	}
	if err := unix.Listen(lfd, 16); err != nil {
		unix.Close(lfd)
		t.Fatalf("server listen: %v", err)
	}
	t.Cleanup(func() { unix.Close(lfd) })

	go func() {
		for {
			cfd, _, err := unix.Accept(lfd)
			if err != nil {
				return
			}
			atomic.AddInt64(count, 1)
			go serveFakeXSocket(cfd, 0)
		}
	}()
	return name
}

// TestSocks5DialerXSocket verifies that a Socks5Dialer configured with an
// xsocket-server reaches the proxy through that server (not the default dialer)
// and still relays data end-to-end.
func TestSocks5DialerXSocket(t *testing.T) {
	echo := startEchoTCPServer(t)
	proxyAddr := startMinimalSocks5Proxy(t)

	var fdRequests int64
	xsPath := startCountingXSocketServer(t, &fdRequests)

	d := NewSocks5Dialer(proxyAddr, Socks5DialerOptions{
		TCPTimeout: 2 * time.Second,
		UDPTimeout: 2 * time.Second,
		NetNS:      &NetNS{XSocket: xsPath},
	})

	conn, err := d.Dial("tcp", echo.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))

	assert.NotZero(t, atomic.LoadInt64(&fdRequests),
		"expected the proxy connection to be obtained via the xsocket-server")
}
