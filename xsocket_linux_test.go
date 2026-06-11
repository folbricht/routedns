//go:build linux

package rdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var xsocketTestSeq uint64

// startFakeXSocketServer starts an in-process stand-in for xsocket-server on an
// abstract Unix socket and returns its path. It speaks the xsocket protocol: it
// reads the 16-byte request, creates the requested socket (in this process's own
// namespace, which is sufficient to exercise the fd-passing/bind/connect logic)
// and returns it via SCM_RIGHTS. If forceErr is non-zero it instead replies with
// that errno and no descriptor.
func startFakeXSocketServer(t *testing.T, forceErr unix.Errno) string {
	t.Helper()
	name := fmt.Sprintf("@rdns-xsocket-test-%d-%d", os.Getpid(), atomic.AddUint64(&xsocketTestSeq, 1))

	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("server socket: %v", err)
	}
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
				return // listener closed
			}
			go serveFakeXSocket(cfd, forceErr)
		}
	}()
	return name
}

func serveFakeXSocket(cfd int, forceErr unix.Errno) {
	defer unix.Close(cfd)

	req := make([]byte, 16)
	n, _, _, _, err := unix.Recvmsg(cfd, req, nil, 0)
	if err != nil || n < len(req) {
		return
	}
	if binary.BigEndian.Uint32(req[0:]) != xsProtocolRequest {
		return
	}
	domain := int(int32(binary.BigEndian.Uint32(req[4:])))
	typ := int(int32(binary.BigEndian.Uint32(req[8:])))
	proto := int(int32(binary.BigEndian.Uint32(req[12:])))

	resp := make([]byte, 8)
	binary.BigEndian.PutUint32(resp[0:], xsProtocolResponse)

	if forceErr != 0 {
		binary.BigEndian.PutUint32(resp[4:], uint32(forceErr))
		_ = unix.Sendmsg(cfd, resp, nil, nil, 0)
		return
	}

	nfd, serr := unix.Socket(domain, typ, proto)
	if serr != nil {
		if e, ok := serr.(unix.Errno); ok {
			binary.BigEndian.PutUint32(resp[4:], uint32(e))
		}
		_ = unix.Sendmsg(cfd, resp, nil, nil, 0)
		return
	}
	defer unix.Close(nfd)
	_ = unix.Sendmsg(cfd, resp, unix.UnixRights(nfd), nil, 0)
}

func TestXSocketGetFd(t *testing.T) {
	path := startFakeXSocketServer(t, 0)
	fd, err := xsocketGetFd(path, unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("xsocketGetFd: %v", err)
	}
	// The returned fd should be a usable socket.
	if _, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil {
		t.Errorf("returned fd is not a socket: %v", err)
	}
	unix.Close(fd)
}

func TestXSocketGetFdError(t *testing.T) {
	path := startFakeXSocketServer(t, unix.EACCES)
	_, err := xsocketGetFd(path, unix.AF_INET, unix.SOCK_STREAM, 0)
	if err == nil {
		t.Fatal("expected an error from the server")
	}
	if !errors.Is(err, unix.EACCES) {
		t.Errorf("expected EACCES, got %v", err)
	}
}

func TestListenXSocketTCP(t *testing.T) {
	path := startFakeXSocketServer(t, 0)
	ln, err := listenXSocket(path, "tcp", "127.0.0.1:0", SocketOptions{})
	if err != nil {
		t.Fatalf("listenXSocket: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			c.Write(buf)
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("got %q, want \"ping\"", buf)
	}
}

func TestListenUDPXSocket(t *testing.T) {
	path := startFakeXSocketServer(t, 0)
	conn, err := listenUDPXSocket(path, "udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, SocketOptions{})
	if err != nil {
		t.Fatalf("listenUDPXSocket: %v", err)
	}
	defer conn.Close()

	client, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Errorf("got %q, want \"ping\"", buf[:n])
	}
}

func TestDialXSocket(t *testing.T) {
	// Local echo server to connect to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			c.Write(buf)
		}
	}()

	path := startFakeXSocketServer(t, 0)
	conn, err := dialXSocket(path, "tcp", ln.Addr().String(), SocketOptions{}, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("dialXSocket: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Errorf("got %q, want \"pong\"", buf)
	}
}

func TestSockaddrFor(t *testing.T) {
	tests := []struct {
		network, address string
		wantDomain       int
		wantErr          bool
	}{
		{"tcp", "127.0.0.1:53", unix.AF_INET, false},
		{"tcp", "[::1]:53", unix.AF_INET6, false},
		{"udp", ":53", unix.AF_INET6, false}, // wildcard defaults to IPv6 (dual-stack)
		{"udp4", ":53", unix.AF_INET, false}, // explicit v4 wildcard
		{"tcp4", "[::1]:53", 0, true},        // v4 network with v6 address
		{"tcp", "127.0.0.1:bogus", 0, true},  // bad port
	}
	for _, tc := range tests {
		domain, _, err := sockaddrFor(tc.network, tc.address)
		if tc.wantErr {
			if err == nil {
				t.Errorf("sockaddrFor(%q, %q): expected error", tc.network, tc.address)
			}
			continue
		}
		if err != nil {
			t.Errorf("sockaddrFor(%q, %q): %v", tc.network, tc.address, err)
			continue
		}
		if domain != tc.wantDomain {
			t.Errorf("sockaddrFor(%q, %q): domain = %d, want %d", tc.network, tc.address, domain, tc.wantDomain)
		}
	}
}
