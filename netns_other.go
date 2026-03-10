//go:build !linux

package rdns

import (
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
func ListenInNetNS(ns *NetNS, network, address string) (net.Listener, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	return net.Listen(network, address)
}

// ListenPacketInNetNS creates a net.PacketConn in the given network namespace.
func ListenPacketInNetNS(ns *NetNS, network, address string) (net.PacketConn, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	return net.ListenPacket(network, address)
}

// ListenUDPInNetNS creates a *net.UDPConn in the given network namespace.
func ListenUDPInNetNS(ns *NetNS, network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	return net.ListenUDP(network, laddr)
}

// DialInNetNS dials a connection in the given network namespace.
func DialInNetNS(ns *NetNS, network, address string, dialer *net.Dialer) (net.Conn, error) {
	if ns != nil && ns.Name != "" {
		return nil, fmt.Errorf("network namespaces are only supported on Linux")
	}
	return dialer.Dial(network, address)
}
