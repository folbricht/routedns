//go:build linux

package rdns

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// NetNS represents a Linux network namespace.
type NetNS struct {
	Name string
}

// nsPath returns the filesystem path for this namespace.
// If Name starts with '/', it is used as-is; otherwise it is looked up
// under /var/run/netns/.
func (ns *NetNS) nsPath() string {
	if filepath.IsAbs(ns.Name) {
		return ns.Name
	}
	return filepath.Join("/var/run/netns", ns.Name)
}

// RunInNetNS executes fn in the given network namespace. If ns is nil or
// has an empty Name, fn is executed in the current namespace (no-op).
// The calling goroutine is locked to its OS thread for the duration.
func RunInNetNS(ns *NetNS, fn func() error) error {
	if ns == nil || ns.Name == "" {
		return fn()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace.
	origNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("failed to open current netns: %w", err)
	}
	defer origNS.Close()

	// Open the target namespace.
	targetNS, err := os.Open(ns.nsPath())
	if err != nil {
		return fmt.Errorf("failed to open target netns %q: %w", ns.Name, err)
	}
	defer targetNS.Close()

	// Switch to target namespace.
	if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("failed to switch to netns %q: %w", ns.Name, err)
	}

	// Always restore the original namespace before returning.
	defer unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET) //nolint:errcheck

	return fn()
}

// ListenInNetNS creates a net.Listener in the given network namespace.
// Socket options (SO_MARK, SO_BINDTODEVICE) are applied before bind() via
// net.ListenConfig.Control so that interface binding works correctly.
func ListenInNetNS(ctx context.Context, ns *NetNS, network, address string, opts SocketOptions) (net.Listener, error) {
	var ln net.Listener
	err := RunInNetNS(ns, func() error {
		lc := net.ListenConfig{Control: opts.dialerControl()}
		var e error
		ln, e = lc.Listen(ctx, network, address)
		return e
	})
	return ln, err
}

// ListenPacketInNetNS creates a net.PacketConn in the given network namespace.
// Socket options (SO_MARK, SO_BINDTODEVICE) are applied before bind() via
// net.ListenConfig.Control so that interface binding works correctly.
func ListenPacketInNetNS(ctx context.Context, ns *NetNS, network, address string, opts SocketOptions) (net.PacketConn, error) {
	var pc net.PacketConn
	err := RunInNetNS(ns, func() error {
		lc := net.ListenConfig{Control: opts.dialerControl()}
		var e error
		pc, e = lc.ListenPacket(ctx, network, address)
		return e
	})
	return pc, err
}

// ListenUDPInNetNS creates a *net.UDPConn in the given network namespace.
// Socket options (SO_MARK, SO_BINDTODEVICE) are applied before bind() via
// net.ListenConfig.Control so that interface binding works correctly.
func ListenUDPInNetNS(ctx context.Context, ns *NetNS, network string, laddr *net.UDPAddr, opts SocketOptions) (*net.UDPConn, error) {
	var conn *net.UDPConn
	err := RunInNetNS(ns, func() error {
		lc := net.ListenConfig{Control: opts.dialerControl()}
		pc, e := lc.ListenPacket(ctx, network, laddr.String())
		if e != nil {
			return e
		}
		var ok bool
		conn, ok = pc.(*net.UDPConn)
		if !ok {
			pc.Close()
			return fmt.Errorf("expected *net.UDPConn, got %T", pc)
		}
		return nil
	})
	return conn, err
}

// DialInNetNS dials a connection in the given network namespace.
func DialInNetNS(ns *NetNS, network, address string, dialer *net.Dialer) (net.Conn, error) {
	var conn net.Conn
	err := RunInNetNS(ns, func() error {
		var e error
		conn, e = dialer.Dial(network, address)
		return e
	})
	return conn, err
}
