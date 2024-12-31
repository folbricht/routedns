package rdns

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

// DoTClient is a DNS-over-TLS resolver.
type DoTClient struct {
	id       string
	endpoint string
	pipeline *Pipeline
	// Pipeline also provides operation metrics.
}

// DoTClientOptions contains options used by the DNS-over-TLS resolver.
type DoTClientOptions struct {
	// Bootstrap address - IP to use for the serivce instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	TLSConfig *tls.Config

	QueryTimeout time.Duration

	// Optional dialer, e.g. proxy
	Dialer Dialer
}

var _ Resolver = &DoTClient{}

// NewDoTClient instantiates a new DNS-over-TLS resolver.
func NewDoTClient(id, endpoint string, opt DoTClientOptions) (*DoTClient, error) {
	if err := validEndpoint(endpoint); err != nil {
		return nil, err
	}

	client := GenericDNSClient{
		Net:       "tcp-tls",
		TLSConfig: opt.TLSConfig,
		Dialer:    opt.Dialer,
		LocalAddr: opt.LocalAddr,
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
		pipeline: NewPipeline(id, endpoint, client, opt.QueryTimeout),
	}, nil
}

// Resolve a DNS query.
func (d *DoTClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	// Packing a message is not always a read-only operation, make a copy
	q = q.Copy()
	log := logger(d.id, q, ci)
	log.Debug("querying upstream resolver", "resolver", d.endpoint, "protocol", "dot")

	// Add padding to the query before sending over TLS
	padQuery(q)
	return d.pipeline.Resolve(q)
}

func (d *DoTClient) String() string {
	return d.id
}
