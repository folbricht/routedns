//go:build linux

package rdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// XSocketServerOptions contain settings for the xsocket fd-server.
type XSocketServerOptions struct {
	// Hand out any socket the client asks for rather than just the
	// IPv4/IPv6 stream and datagram sockets RouteDNS itself uses.
	Unrestricted bool

	// Permissions applied to the Unix socket after it is created. Zero
	// leaves the permissions at what the process umask produces. Has no
	// effect on abstract sockets.
	SocketMode fs.FileMode
}

// XSocketServer implements the server side of the xsocket protocol, see
// https://github.com/koro666/xsocket. It listens on an AF_UNIX/SOCK_SEQPACKET
// socket and returns socket file descriptors created in its own network
// namespace to clients via SCM_RIGHTS. It can be used in place of
// xsocket-server, typically started inside a network namespace with
// "ip netns exec". A leading '@' in the path denotes an abstract socket.
type XSocketServer struct {
	path string
	opt  XSocketServerOptions

	mu     sync.Mutex
	ln     *net.UnixListener
	closed bool
}

func NewXSocketServer(path string, opt XSocketServerOptions) *XSocketServer {
	return &XSocketServer{path: path, opt: opt}
}

func (s *XSocketServer) String() string {
	return "XSocketServer(" + s.path + ")"
}

// Start creates the Unix socket and serves requests until Stop is called.
func (s *XSocketServer) Start() error {
	ln, err := s.listen()
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ln.Close()
	}
	s.ln = ln
	s.mu.Unlock()

	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// Stop closes the listening socket, removing it from the filesystem.
func (s *XSocketServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *XSocketServer) listen() (*net.UnixListener, error) {
	abstract := strings.HasPrefix(s.path, "@")
	addr := &net.UnixAddr{Name: s.path, Net: "unixpacket"}
	ln, err := net.ListenUnix("unixpacket", addr)
	if err != nil && !abstract && errors.Is(err, syscall.EADDRINUSE) {
		// A socket file left behind by an earlier run prevents binding. If
		// no server is accepting connections on it, remove it and retry.
		if conn, derr := net.DialTimeout("unixpacket", s.path, time.Second); derr == nil {
			conn.Close()
			return nil, fmt.Errorf("socket %q is in use by another server", s.path)
		} else if !errors.Is(derr, syscall.ECONNREFUSED) {
			return nil, err
		}
		Log.Info("removing stale socket", "socket", s.path)
		if rerr := os.Remove(s.path); rerr != nil {
			return nil, err
		}
		ln, err = net.ListenUnix("unixpacket", addr)
	}
	if err != nil {
		return nil, err
	}
	if s.opt.SocketMode != 0 && !abstract {
		if err := os.Chmod(s.path, s.opt.SocketMode); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

// handle serves one client connection. Each 16-byte request message produces
// one response message; the connection is closed on EOF or a malformed
// request.
func (s *XSocketServer) handle(conn *net.UnixConn) {
	defer conn.Close()
	req := make([]byte, 16)
	for {
		n, err := conn.Read(req)
		if err != nil || n == 0 { // EOF or read failure
			return
		}
		if n < len(req) || binary.BigEndian.Uint32(req[0:]) != xsProtocolRequest {
			Log.Debug("malformed xsocket request, closing connection")
			return
		}
		domain := int(binary.BigEndian.Uint32(req[4:]))
		typ := int(binary.BigEndian.Uint32(req[8:]))
		proto := int(binary.BigEndian.Uint32(req[12:]))

		fd := -1
		var errno unix.Errno
		if !s.opt.Unrestricted && !allowedSocket(domain, typ, proto) {
			Log.Warn("rejecting xsocket request", "domain", domain, "type", typ, "proto", proto)
			errno = unix.EPERM
		} else if fd, err = unix.Socket(domain, typ|unix.SOCK_CLOEXEC, proto); err != nil {
			fd = -1
			if !errors.As(err, &errno) {
				errno = unix.EINVAL
			}
		}

		resp := make([]byte, 8)
		binary.BigEndian.PutUint32(resp[0:], xsProtocolResponse)
		binary.BigEndian.PutUint32(resp[4:], uint32(errno))
		var oob []byte
		if fd >= 0 {
			oob = unix.UnixRights(fd)
		}
		_, _, werr := conn.WriteMsgUnix(resp, oob, nil)
		if fd >= 0 {
			unix.Close(fd) // the client received a duplicate
		}
		if werr != nil {
			return
		}
	}
}

// allowedSocket is the default allow-list: the IPv4/IPv6 TCP and UDP sockets
// RouteDNS requests through xsocket.
func allowedSocket(domain, typ, proto int) bool {
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return false
	}
	switch typ &^ (unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK) {
	case unix.SOCK_STREAM:
		return proto == 0 || proto == unix.IPPROTO_TCP
	case unix.SOCK_DGRAM:
		return proto == 0 || proto == unix.IPPROTO_UDP
	}
	return false
}
