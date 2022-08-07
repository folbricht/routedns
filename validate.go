package rdns

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Returns nil if the endpoint address in the form of <host>:<port> is a valid.
func validEndpoint(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}
	// See if we have a valid IP
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	return validHostname(host)
}

// Returns nil if the given name is a valid hostname as per https://tools.ietf.org/html/rfc3696#section-2
// and https://tools.ietf.org/html/rfc1123#page-13
func validHostname(name string) error {
	if name == "" {
		return errors.New("hostname empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("invalid hostname %q: too long", name)
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for _, label := range labels {
		for _, c := range label {
			if label == "" {
				return fmt.Errorf("invalid hostname %q: empty label", name)
			}
			if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return fmt.Errorf("invalid hostname %q: label can not start or end with -", name)
			}
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
			default:
				return fmt.Errorf("invalid hostname %q: invalid character %q", name, string(c))
			}
		}
	}
	// The last label can not be all-numeric
	for _, c := range labels[len(labels)-1] {
		if c < '0' || c > '9' {
			return nil
		}
	}
	return fmt.Errorf("invalid hostname %q: last label can not be all numeric", name)
}
