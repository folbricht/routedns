package rdns

import (
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// DoTClient is a DNS-over-TLS resolver.
type DoTClient struct {
	id       string
	endpoint string
	pipeline *Pipeline
}

// DoTClientOptions contains options used by the DNS-over-TLS resolver.
type DoTClientOptions struct {
	// Bootstrap address - IP to use for the serivce instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	TLSConfig *tls.Config
}

var _ Resolver = &DoTClient{}

// NewDoTClient instantiates a new DNS-over-TLS resolver.
func NewDoTClient(id, endpoint string, opt DoTClientOptions) (*DoTClient, error) {
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: opt.TLSConfig,
	}
	// If a bootstrap address was provided, we need to use the IP for the connection but the
	// hostname in the TLS handshake. The DNS library doesn't support custom dialers, so
	// instead set the ServerName in the TLS config to the name in the endpoint config, and
	// replace the name in the endpoint with the bootstrap IP.
	if opt.BootstrapAddr != "" {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse dot endpoint '%s'", endpoint)
		}
		client.TLSConfig.ServerName = host
		endpoint = net.JoinHostPort(opt.BootstrapAddr, port)
	}
	return &DoTClient{
		id:       id,
		endpoint: endpoint,
		pipeline: NewPipeline(endpoint, client),
	}, nil
}

// Resolve a DNS query.
func (d *DoTClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	Log.WithFields(logrus.Fields{
		"id":       d.id,
		"client":   ci.SourceIP,
		"qname":    qName(q),
		"resolver": d.endpoint,
		"protocol": "dot",
	}).Debug("querying upstream resolver")

	// Add padding to the query before sending over TLS
	padQuery(q)
	return d.pipeline.Resolve(q)
}

func (d *DoTClient) String() string {
	return d.id
}
