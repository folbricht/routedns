package rdns

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DNSClient represents a simple DNS resolver for UDP or TCP.
type DNSClient struct {
	id       string
	endpoint string
	net      string
	pipeline *Pipeline
	// Pipeline also provides operation metrics.
}

type DNSClientOptions struct {
	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete.
	Timeout time.Duration
}

var _ Resolver = &DNSClient{}

// NewDNSClient returns a new instance of DNSClient which is a plain DNS resolver
// that supports pipelining over a single connection.
func NewDNSClient(id, endpoint, network string, opt DNSClientOptions) (*DNSClient, error) {
	if err := validEndpoint(endpoint); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: opt.Timeout}
	if opt.LocalAddr != nil {
		switch network {
		case "tcp":
			dialer.LocalAddr = &net.TCPAddr{IP: opt.LocalAddr}
		case "udp":
			dialer.LocalAddr = &net.UDPAddr{IP: opt.LocalAddr}
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
	}, nil
}

// Resolve a DNS query.
func (d *DNSClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	logger(d.id, q, ci).WithFields(logrus.Fields{
		"resolver": d.endpoint,
		"protocol": d.net,
	}).Debug("querying upstream resolver")

	// Remove padding before sending over the wire in plain
	stripPadding(q)
	return d.pipeline.Resolve(q)
}

func (d *DNSClient) String() string {
	return d.id
}
