//go:build !linux

package rdns

import (
	"fmt"
	"net"
	"time"
)

// dialXSocket is referenced from platform-agnostic code. xsocket relies on
// Linux-specific facilities (network namespaces, SCM_RIGHTS fd passing into a
// namespace), so it is unsupported elsewhere.
func dialXSocket(path, network, address string, opts SocketOptions, localAddr net.IP, timeout time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("xsocket is only supported on Linux")
}
