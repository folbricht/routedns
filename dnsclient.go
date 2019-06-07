package rdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// DNSClient represents a simple DNS resolver for UDP or TCP.
type DNSClient struct {
	*dns.Client
	endpoint string
}

var _ Resolver = &DNSClient{}

// NewDNSClient returns a new instance of DNSClient which is a simple DNS resolver.
func NewDNSClient(endpoint, net string) *DNSClient {
	return &DNSClient{
		Client: &dns.Client{
			Net: net,
		},
		endpoint: endpoint,
	}
}

// Resolve a DNS query.
func (d *DNSClient) Resolve(q *dns.Msg) (*dns.Msg, error) {
	Log.Printf("sending query for '%s' to %s/%s", qName(q), d.endpoint, d.Net)
	a, _, err := d.Exchange(q, d.endpoint)
	return a, err
}

func (d *DNSClient) String() string {
	return fmt.Sprintf("DNS(%s)", d.endpoint)
}
