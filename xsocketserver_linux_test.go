//go:build linux

package rdns

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// startXSocketServer runs an XSocketServer on a socket in a temp directory
// and returns the socket path. Server shutdown is handled via test cleanup.
func startXSocketServer(t *testing.T, opt XSocketServerOptions) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xs.sock")
	startXSocketServerOn(t, path, opt)
	return path
}

func startXSocketServerOn(t *testing.T, path string, opt XSocketServerOptions) {
	t.Helper()
	srv := NewXSocketServer(path, opt)
	done := make(chan error, 1)
	go func() { done <- srv.Start() }()
	t.Cleanup(func() {
		srv.Stop()
		require.NoError(t, <-done)
	})
	// Wait for the server to accept connections
	var err error
	for i := 0; i < 100; i++ {
		var conn net.Conn
		if conn, err = net.Dial("unixpacket", path); err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("xsocket server did not come up: %v", err)
}

func TestXSocketServerGetFd(t *testing.T) {
	path := startXSocketServer(t, XSocketServerOptions{})

	// Multiple sequential requests, each on its own connection
	for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
		fd, err := xsocketGetFd(path, unix.AF_INET, typ, 0)
		require.NoError(t, err)
		soType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		require.NoError(t, err)
		require.Equal(t, typ, soType)
		require.NoError(t, unix.Close(fd))
	}
}

func TestXSocketServerAbstract(t *testing.T) {
	path := fmt.Sprintf("@routedns-test-xsocket-%d", os.Getpid())
	startXSocketServerOn(t, path, XSocketServerOptions{})

	fd, err := xsocketGetFd(path, unix.AF_INET6, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))
}

func TestXSocketServerListenAndDial(t *testing.T) {
	path := startXSocketServer(t, XSocketServerOptions{})

	// Listen on a TCP socket obtained from the server, then connect to it
	// with a socket also obtained from the server.
	ln, err := listenXSocket(path, "tcp", "127.0.0.1:0", SocketOptions{})
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err
	}()

	conn, err := dialXSocket(path, "tcp", ln.Addr().String(), SocketOptions{}, nil, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, <-accepted)
}

func TestXSocketServerRestricted(t *testing.T) {
	path := startXSocketServer(t, XSocketServerOptions{})

	// Non-IP sockets are refused with EPERM by default
	_, err := xsocketGetFd(path, unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.ErrorIs(t, err, unix.EPERM)
}

func TestXSocketServerUnrestricted(t *testing.T) {
	path := startXSocketServer(t, XSocketServerOptions{Unrestricted: true})

	fd, err := xsocketGetFd(path, unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))

	// Invalid requests still report the socket() errno
	_, err = xsocketGetFd(path, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_UDP)
	require.ErrorIs(t, err, unix.EPROTONOSUPPORT)
}

func TestXSocketServerMalformed(t *testing.T) {
	path := startXSocketServer(t, XSocketServerOptions{})

	// A request with a bad signature closes the connection without a response
	conn, err := net.Dial("unixpacket", path)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("bad request none"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := conn.Read(make([]byte, 8))
	require.Error(t, err)
	require.Equal(t, 0, n)
}

func TestXSocketServerSocketMode(t *testing.T) {
	path := startXSocketServer(t, XSocketServerOptions{SocketMode: 0660})

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0660), info.Mode().Perm())
}

func TestXSocketServerStaleSocket(t *testing.T) {
	// Leave a socket file behind that nothing is listening on
	path := filepath.Join(t.TempDir(), "xs.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Bind(fd, &unix.SockaddrUnix{Name: path}))
	require.NoError(t, unix.Close(fd))

	// The server should remove the stale file and start up
	startXSocketServerOn(t, path, XSocketServerOptions{})
	fd, err = xsocketGetFd(path, unix.AF_INET, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))
}

func TestXSocketServerInUse(t *testing.T) {
	// A second server on the same socket should refuse to start
	path := startXSocketServer(t, XSocketServerOptions{})
	srv := NewXSocketServer(path, XSocketServerOptions{})
	err := srv.Start()
	require.ErrorContains(t, err, "in use")
}
