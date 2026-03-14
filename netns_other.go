//go:build !linux

package rdns

import (
	"context"
	"fmt"
	"net"
)

// NetNS represents a Linux network namespace.
// On non-Linux platforms, configuring a namespace returns an error.
type NetNS struct {
	Name string
}

// RunInNetNS executes fn in the given network namespace. On non-Linux
// platforms this returns an error if a namespace is configured.
func RunInNetNS(ns *NetNS, fn func() error) error {
	if ns == nil || ns.Name == "" {
		return fn()
	}
	return fmt.Errorf("network namespaces are only supported on Linux")
}

// ListenInNetNS creates a net.Listener in the given network namespace.
func ListenInNetNS(ctx context.Context, ns *NetNS, network, address string, opts SocketOptions) (net.Listener, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	lc := net.ListenConfig{Control: opts.dialerControl()}
	return lc.Listen(ctx, network, address)
}

// ListenPacketInNetNS creates a net.PacketConn in the given network namespace.
func ListenPacketInNetNS(ctx context.Context, ns *NetNS, network, address string, opts SocketOptions) (net.PacketConn, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	lc := net.ListenConfig{Control: opts.dialerControl()}
	return lc.ListenPacket(ctx, network, address)
}

// ListenUDPInNetNS creates a *net.UDPConn in the given network namespace.
func ListenUDPInNetNS(ctx context.Context, ns *NetNS, network string, laddr *net.UDPAddr, opts SocketOptions) (*net.UDPConn, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	lc := net.ListenConfig{Control: opts.dialerControl()}
	pc, err := lc.ListenPacket(ctx, network, laddr.String())
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

// DialInNetNS dials a connection in the given network namespace.
func DialInNetNS(ns *NetNS, network, address string, dialer *net.Dialer) (net.Conn, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	return dialer.Dial(network, address)
}
