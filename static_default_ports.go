package rdns

import (
	"fmt"
	"net"
	"net/url"
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
func AddressWithDefaultForHttp(addr, defaultPort string) string {
	var addrUri string = ""
	if addr == "" {
		return addr
	}

	if strings.Contains(addr, "{") {
		var splitAddr = strings.Split(addr, "{")
		addrUri = splitAddr[1]
		addr = splitAddr[0]

	}

	u, err := url.Parse(addr)
	if err != nil {
		return addr
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Host, defaultPort)
	}
	if u.Scheme == "" { // no url, just host+port
		return u.Host
	}
	if addrUri == "" {
		return u.String() + addrUri // re-assemble the address, now with port
	} else {
		return u.String() // re-assemble the address, now with port
	}
}
