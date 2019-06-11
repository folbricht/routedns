package rdns

import (
	"fmt"
	"net"
)

// Listener is an interface for a DNS listener.
type Listener interface {
	Start() error
	fmt.Stringer
}

// ClientInfo carries information about the client making the request that
// can be used to route requests.
type ClientInfo struct {
	SourceIP net.IP
}
