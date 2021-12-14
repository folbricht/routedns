package rdns

import (
	"fmt"
	"net"
	"os"
	"strings"
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
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Errorf(err.Error())
		os.Exit(44)
	}
	var isPortEmpty bool = port == ""
	var isHttpProtocol bool = strings.Contains(addr, "https://")
	if host == "" {
		return net.JoinHostPort(host, defaultPort)
	} else if isHttpProtocol {
		return addr
	} else if isPortEmpty {
		return net.JoinHostPort(addr, defaultPort)
	} else {
		return addr
	}
}
