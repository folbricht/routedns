//go:build linux

package rdns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// xsocket protocol signatures, see https://github.com/koro666/xsocket. All
// protocol fields are 32-bit and exchanged in network byte order over an
// AF_UNIX/SOCK_SEQPACKET connection.
const (
	xsProtocolRequest  uint32 = 0x58533031 // "XS01"
	xsProtocolResponse uint32 = 0x58533032 // "XS02"
)

// xsocketGetFd asks the xsocket-server listening on the given Unix socket path
// to create a socket(domain, typ, proto) in its network namespace and return
// the resulting (unbound) file descriptor via SCM_RIGHTS. The caller owns the
// returned fd and is responsible for closing it. Abstract sockets are supported
// by prefixing the path with '@'.
func xsocketGetFd(path string, domain, typ, proto int) (int, error) {
	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, os.NewSyscallError("socket", err)
	}
	defer unix.Close(cfd)

	// SockaddrUnix translates a leading '@' into the NUL byte that denotes an
	// abstract socket, so the path can be passed through unchanged.
	if err := unix.Connect(cfd, &unix.SockaddrUnix{Name: path}); err != nil {
		return -1, fmt.Errorf("connecting to xsocket-server %q: %w", path, err)
	}

	req := make([]byte, 16)
	binary.BigEndian.PutUint32(req[0:], xsProtocolRequest)
	binary.BigEndian.PutUint32(req[4:], uint32(domain))
	binary.BigEndian.PutUint32(req[8:], uint32(typ))
	binary.BigEndian.PutUint32(req[12:], uint32(proto))
	if err := unix.Send(cfd, req, 0); err != nil {
		return -1, os.NewSyscallError("send", err)
	}
	// Half-close the write side to signal the end of the request.
	_ = unix.Shutdown(cfd, unix.SHUT_WR)

	resp := make([]byte, 8)
	oob := make([]byte, unix.CmsgSpace(4)) // room for a single fd
	n, oobn, _, _, err := unix.Recvmsg(cfd, resp, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, os.NewSyscallError("recvmsg", err)
	}
	if n < len(resp) {
		return -1, fmt.Errorf("xsocket: short response (%d bytes)", n)
	}
	if sig := binary.BigEndian.Uint32(resp[0:]); sig != xsProtocolResponse {
		return -1, fmt.Errorf("xsocket: invalid response signature %#x", sig)
	}

	// Always parse any descriptors that came back so we never leak one, even
	// when the server also reported an error.
	var fds []int
	if scms, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
		for i := range scms {
			if rights, rerr := unix.ParseUnixRights(&scms[i]); rerr == nil {
				fds = append(fds, rights...)
			}
		}
	}
	if errno := binary.BigEndian.Uint32(resp[4:]); errno != 0 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return -1, fmt.Errorf("xsocket-server returned error: %w", unix.Errno(errno))
	}
	if len(fds) == 0 {
		return -1, fmt.Errorf("xsocket: no file descriptor in response")
	}
	// Defensive: close any unexpected extra descriptors.
	for _, fd := range fds[1:] {
		unix.Close(fd)
	}
	return fds[0], nil
}

// listenXSocket obtains a TCP socket from the xsocket-server, binds it to
// address and starts listening, returning a net.Listener backed by that fd.
func listenXSocket(path, network, address string, opts SocketOptions) (net.Listener, error) {
	domain, sa, err := sockaddrFor(network, address)
	if err != nil {
		return nil, err
	}
	fd, err := xsocketGetFd(path, domain, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	if err := setupListenSocket(fd, domain, network, opts); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("binding xsocket fd to %q: %w", address, err)
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("listen", err)
	}
	f := os.NewFile(uintptr(fd), "xsocket:"+address)
	ln, err := net.FileListener(f)
	f.Close() // FileListener dups the fd; release our copy.
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// listenPacketXSocket obtains a UDP socket from the xsocket-server, binds it to
// address and returns a net.PacketConn backed by that fd.
func listenPacketXSocket(path, network, address string, opts SocketOptions) (net.PacketConn, error) {
	domain, sa, err := sockaddrFor(network, address)
	if err != nil {
		return nil, err
	}
	fd, err := xsocketGetFd(path, domain, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	if err := setupListenSocket(fd, domain, network, opts); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("binding xsocket fd to %q: %w", address, err)
	}
	f := os.NewFile(uintptr(fd), "xsocket:"+address)
	pc, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	return pc, nil
}

// listenUDPXSocket is like listenPacketXSocket but returns the concrete
// *net.UDPConn type used by the QUIC-based transports.
func listenUDPXSocket(path, network string, laddr *net.UDPAddr, opts SocketOptions) (*net.UDPConn, error) {
	address := ":0"
	if laddr != nil {
		address = laddr.String()
	}
	pc, err := listenPacketXSocket(path, network, address, opts)
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("expected *net.UDPConn, got %T", pc)
	}
	return conn, nil
}

// dialXSocket obtains a socket from the xsocket-server and connects it to the
// remote address, optionally binding to localAddr first. The connect honours
// timeout (0 means no timeout).
func dialXSocket(path, network, address string, opts SocketOptions, localAddr net.IP, timeout time.Duration) (net.Conn, error) {
	domain, sa, err := sockaddrFor(network, address)
	if err != nil {
		return nil, err
	}
	var typ int
	switch {
	case strings.HasPrefix(network, "tcp"):
		typ = unix.SOCK_STREAM
	case strings.HasPrefix(network, "udp"):
		typ = unix.SOCK_DGRAM
	default:
		return nil, fmt.Errorf("unsupported network %q for xsocket dial", network)
	}
	fd, err := xsocketGetFd(path, domain, typ, 0)
	if err != nil {
		return nil, err
	}
	if err := opts.applyToFd(uintptr(fd)); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if localAddr != nil && !localAddr.IsUnspecified() {
		_, lsa := sockaddrFromIP(localAddr, 0)
		if err := unix.Bind(fd, lsa); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("binding to local address %s: %w", localAddr, err)
		}
	}
	if err := connectFd(fd, sa, timeout); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "xsocket:"+address)
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// setupListenSocket applies socket options (before bind) and the defaults the
// Go net package sets on listening sockets: SO_REUSEADDR, and for IPv6 sockets
// the IPV6_V6ONLY flag matching the requested network family.
func setupListenSocket(fd, domain int, network string, opts SocketOptions) error {
	if err := opts.applyToFd(uintptr(fd)); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return os.NewSyscallError("setsockopt SO_REUSEADDR", err)
	}
	if domain == unix.AF_INET6 {
		v6only := 0
		if networkIPVersion(network) == 6 {
			v6only = 1
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, v6only); err != nil {
			return os.NewSyscallError("setsockopt IPV6_V6ONLY", err)
		}
	}
	return nil
}

// connectFd performs a non-blocking connect honouring the given timeout.
func connectFd(fd int, sa unix.Sockaddr, timeout time.Duration) error {
	if err := unix.SetNonblock(fd, true); err != nil {
		return os.NewSyscallError("setnonblock", err)
	}
	err := unix.Connect(fd, sa)
	if err == nil {
		return nil
	}
	if err != unix.EINPROGRESS && err != unix.EINTR {
		return os.NewSyscallError("connect", err)
	}

	timeoutMs := -1
	if timeout > 0 {
		if timeoutMs = int(timeout / time.Millisecond); timeoutMs == 0 {
			timeoutMs = 1
		}
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	for {
		n, perr := unix.Poll(pfd, timeoutMs)
		if perr == unix.EINTR {
			continue
		}
		if perr != nil {
			return os.NewSyscallError("poll", perr)
		}
		if n == 0 {
			return &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
		}
		break
	}
	soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return os.NewSyscallError("getsockopt", err)
	}
	if soErr != 0 {
		return os.NewSyscallError("connect", unix.Errno(soErr))
	}
	return nil
}

// sockaddrFor resolves a network/address pair (as used by net.Listen/net.Dial)
// into the socket domain and a unix.Sockaddr. Hostnames are resolved in the
// current (routedns) network namespace. An empty host binds to the wildcard
// address; the family follows an explicit "4"/"6" network suffix, defaulting to
// IPv6 (dual-stack) otherwise.
func sockaddrFor(network, address string) (int, unix.Sockaddr, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0, nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid port %q in %q: %w", portStr, address, err)
	}
	ipVersion := networkIPVersion(network)

	var ip net.IP
	switch {
	case host == "":
		if ipVersion == 4 {
			ip = net.IPv4zero
		} else {
			ip = net.IPv6unspecified
		}
	default:
		if ip = net.ParseIP(host); ip == nil {
			lookupNet := "ip"
			switch ipVersion {
			case 4:
				lookupNet = "ip4"
			case 6:
				lookupNet = "ip6"
			}
			ips, err := net.DefaultResolver.LookupIP(context.Background(), lookupNet, host)
			if err != nil {
				return 0, nil, fmt.Errorf("resolving %q: %w", host, err)
			}
			if len(ips) == 0 {
				return 0, nil, fmt.Errorf("no addresses found for %q", host)
			}
			ip = ips[0]
		}
	}

	if ipVersion == 4 && ip.To4() == nil {
		return 0, nil, fmt.Errorf("address %q is not IPv4 but network is %q", address, network)
	}
	if ipVersion == 6 && ip.To4() != nil {
		return 0, nil, fmt.Errorf("address %q is not IPv6 but network is %q", address, network)
	}

	domain, sa := sockaddrFromIP(ip, port)
	return domain, sa, nil
}

// sockaddrFromIP builds a unix.Sockaddr (and its domain) for an IP and port.
func sockaddrFromIP(ip net.IP, port int) (int, unix.Sockaddr) {
	if ip4 := ip.To4(); ip4 != nil {
		sa := &unix.SockaddrInet4{Port: port}
		copy(sa.Addr[:], ip4)
		return unix.AF_INET, sa
	}
	sa := &unix.SockaddrInet6{Port: port}
	copy(sa.Addr[:], ip.To16())
	return unix.AF_INET6, sa
}

// networkIPVersion returns 4 or 6 for an explicit "tcp4"/"udp6" style suffix,
// or 0 when the network is family-agnostic ("tcp"/"udp").
func networkIPVersion(network string) int {
	switch {
	case strings.HasSuffix(network, "4"):
		return 4
	case strings.HasSuffix(network, "6"):
		return 6
	default:
		return 0
	}
}
