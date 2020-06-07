package rdns

import (
	"crypto/tls"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DNSClient represents a simple DNS resolver for UDP or TCP.
type DNSClient struct {
	id       string
	endpoint string
	net      string
	pipeline *Pipeline
}

var _ Resolver = &DNSClient{}

// NewDNSClient returns a new instance of DNSClient which is a plain DNS resolver
// that supports pipelining over a single connection.
func NewDNSClient(id, endpoint, net string) *DNSClient {
	client := &dns.Client{
		Net:       net,
		TLSConfig: &tls.Config{},
	}
	return &DNSClient{
		id:       id,
		net:      net,
		endpoint: endpoint,
		pipeline: NewPipeline(endpoint, client),
	}
}

// Resolve a DNS query.
func (d *DNSClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	Log.WithFields(logrus.Fields{
		"id":       d.id,
		"client":   ci.SourceIP,
		"qname":    qName(q),
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
