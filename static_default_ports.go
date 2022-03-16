package rdns

import (
	"net"
	"net/url"
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

// AddressWithDefault takes an endpoint or a URL and adds a port unless it
// already has one. If it fails to parse addr, it returns the original value.
func AddressWithDefault(addr, defaultPort string) string {
	// Endpoints like DoH can contain URL templates, so we want to strip those
	// off first
	parts := strings.SplitN(addr, "{", 2)
	endpointPart := parts[0]
	var templatePart string
	if len(parts) == 2 {
		templatePart = "{" + parts[1]
	}

	// Now let's see if it's a URL. If it is, it'll have a "/" in it
	if strings.Contains(endpointPart, "/") {
		u, err := url.Parse(endpointPart)
		if err != nil {
			return addr
		}
		if u.Port() == "" {
			u.Host = net.JoinHostPort(u.Host, defaultPort)
		}
		return u.String() + templatePart
	}

	// Here we know it's not a URL, so it should be either <host>:<port> or just <host>
	if strings.Contains(endpointPart, ":") {
		return addr
	}
	return net.JoinHostPort(endpointPart, defaultPort)
}
