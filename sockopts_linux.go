//go:build linux

package rdns

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// applyToFd sets the configured socket options on the given file descriptor.
func (s SocketOptions) applyToFd(fd uintptr) error {
	if s.FWMark > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(s.FWMark)); err != nil {
			return fmt.Errorf("failed to set SO_MARK to %d: %w", s.FWMark, err)
		}
	}
	if s.BindInterface != "" {
		if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, s.BindInterface); err != nil {
			return fmt.Errorf("failed to set SO_BINDTODEVICE to %q: %w", s.BindInterface, err)
		}
	}
	return nil
}

// dialerControl returns a function suitable for use as net.Dialer.Control or
// net.ListenConfig.Control that applies the configured socket options.
// Returns nil if no options are set.
func (s SocketOptions) dialerControl() func(string, string, syscall.RawConn) error {
	if !s.active() {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = s.applyToFd(fd)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

// applyToConn applies socket options to an existing connection or listener.
// The argument must implement syscall.Conn (e.g. *net.UDPConn, *net.TCPListener).
func (s SocketOptions) applyToConn(conn any) error {
	if !s.active() {
		return nil
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("cannot apply socket options: %T does not implement syscall.Conn", conn)
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = s.applyToFd(fd)
	})
	if err != nil {
		return err
	}
	return sockErr
}
