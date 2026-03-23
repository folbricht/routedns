package rdns

import (
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

// proxyProtocolListener wraps a net.Listener with PROXY protocol v1/v2
// header parsing if enabled. When enabled, accepted connections return
// the real client IP from RemoteAddr() as conveyed by an upstream load
// balancer via the PROXY protocol header.
func proxyProtocolListener(ln net.Listener, enabled bool) net.Listener {
	if !enabled {
		return ln
	}
	return &proxyproto.Listener{Listener: ln}
}
