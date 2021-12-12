package rdns

import (
	"net"
)

var (
	DoQPort      string = "8853"
	DohQuicPort  string = "1443"
	DoTPort      string = "853"
	DTLSPort     string = DoTPort
	DoHPort      string = "443"
	PlainDNSPort        = "53"
)

func AddressWithDefault(addr, defaultPort string) string {
	_, port, _ := net.SplitHostPort(addr)
	var isPortEmpty bool = len(port) > 0
	if isPortEmpty == false {
		return net.JoinHostPort(addr, defaultPort)
	} else {
		return addr
	}
}
