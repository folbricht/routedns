package rdns

import (
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DNSClient represents a simple DNS resolver for UDP or TCP.
type DNSClient struct {
	id       string
	endpoint string
	net      string
	pipeline *Pipeline // Pipeline also provides operation metrics.
	opt      DNSClientOptions
}

type DNSClientOptions struct {
	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	// Sets the EDNS0 UDP size for all queries sent upstream. If set to 0, queries
	// are not changed.
	UDPSize uint16
}

var _ Resolver = &DNSClient{}

// NewDNSClient returns a new instance of DNSClient which is a plain DNS resolver
// that supports pipelining over a single connection.
func NewDNSClient(id, endpoint, network string, opt DNSClientOptions) (*DNSClient, error) {
	if err := validEndpoint(endpoint); err != nil {
		return nil, err
	}
	// Use a custom dialer if a local address was provided
	var dialer *net.Dialer
	if opt.LocalAddr != nil {
		switch network {
		case "tcp":
			dialer = &net.Dialer{LocalAddr: &net.TCPAddr{IP: opt.LocalAddr}}
		case "udp":
			dialer = &net.Dialer{LocalAddr: &net.UDPAddr{IP: opt.LocalAddr}}
		}
	}

	client := &dns.Client{
		Net:       network,
		Dialer:    dialer,
		TLSConfig: &tls.Config{},
		UDPSize:   4096,
	}
	return &DNSClient{
		id:       id,
		net:      network,
		endpoint: endpoint,
		pipeline: NewPipeline(id, endpoint, client),
		opt:      opt,
	}, nil
}

// Resolve a DNS query.
func (d *DNSClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	logger(d.id, q, ci).WithFields(logrus.Fields{
		"resolver": d.endpoint,
		"protocol": d.net,
	}).Debug("querying upstream resolver")

	q = setUDPSize(q, d.opt.UDPSize)

	// Remove padding before sending over the wire in plain
	stripPadding(q)
	return d.pipeline.Resolve(q)
}

func (d *DNSClient) String() string {
	return d.id
}
