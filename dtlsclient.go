package rdns

import (
	"fmt"
	"net"
	"strconv"

	"github.com/miekg/dns"
	"github.com/pion/dtls/v2"
	"github.com/sirupsen/logrus"
)

// DTLSClient is a DNS-over-DTLS resolver.
type DTLSClient struct {
	endpoint string
	pipeline *Pipeline
}

// DTLSClientOptions contains options used by the DNS-over-DTLS resolver.
type DTLSClientOptions struct {
	// Bootstrap address - IP to use for the serivce instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	DTLSConfig *dtls.Config
}

var _ Resolver = &DTLSClient{}

// NewDTLSClient instantiates a new DNS-over-TLS resolver.
func NewDTLSClient(endpoint string, opt DTLSClientOptions) (*DTLSClient, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	// If a bootstrap address was provided, we need to use the IP for the connection but the
	// hostname in the TLS handshake.
	var ip net.IP
	if opt.BootstrapAddr != "" {
		opt.DTLSConfig.ServerName = host
		ip = net.ParseIP(opt.BootstrapAddr)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse bootstrap address '%s'", opt.BootstrapAddr)
		}
	} else {
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		if len(ips) < 1 {
			return nil, fmt.Errorf("failed to lookup '%s'", host)
		}
		ip = ips[0]
	}
	addr := &net.UDPAddr{IP: ip, Port: p}

	client := &dtlsDialer{
		addr:       addr,
		dtlsConfig: opt.DTLSConfig,
	}
	return &DTLSClient{
		endpoint: endpoint,
		pipeline: NewPipeline(endpoint, client),
	}, nil
}

// Resolve a DNS query.
func (d *DTLSClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	Log.WithFields(logrus.Fields{
		"client":   ci.SourceIP,
		"qname":    qName(q),
		"resolver": d.endpoint,
		"protocol": "dtls",
	}).Debug("querying upstream resolver")

	// Add padding to the query before sending over TLS
	padQuery(q)
	return d.pipeline.Resolve(q)
}

func (d *DTLSClient) String() string {
	return fmt.Sprintf("DTLS(%s)", d.endpoint)
}

type dtlsDialer struct {
	addr       *net.UDPAddr
	dtlsConfig *dtls.Config
}

func (d dtlsDialer) Dial(address string) (*dns.Conn, error) {
	c, err := dtls.Dial("udp", d.addr, d.dtlsConfig)
	return &dns.Conn{Conn: c}, err
}
