package rdns

import (
	"crypto/tls"
	"fmt"

	"github.com/miekg/dns"
)

// DNSClient represents a simple DNS resolver for UDP or TCP.
type DNSClient struct {
	endpoint string
	net      string
	pipeline *Pipeline
}

var _ Resolver = &DNSClient{}

// NewDNSClient returns a new instance of DNSClient which is a plain DNS resolver
// that supports pipelining over a single connection.
func NewDNSClient(endpoint, net string) *DNSClient {
	client := &dns.Client{
		Net:       net,
		TLSConfig: &tls.Config{},
	}
	return &DNSClient{
		net:      net,
		endpoint: endpoint,
		pipeline: NewPipeline(endpoint, client),
	}

}

// Resolve a DNS query.
func (d *DNSClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	Log.Printf("sending query for '%s' to %s/%s", qName(q), d.endpoint, d.net)
	return d.pipeline.Resolve(q)
}

func (d *DNSClient) String() string {
	return fmt.Sprintf("DNS(%s)", d.endpoint)
}
