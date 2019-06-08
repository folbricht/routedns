package rdns

import (
	"crypto/tls"
	"fmt"

	"github.com/miekg/dns"
)

// DoTClient is a DNS-over-TLS resolver.
type DoTClient struct {
	endpoint string
	conn     *Pipeline
}

var _ Resolver = &DoTClient{}

// NewDoTClient instantiates a new DNS-over-TLS resolver.
func NewDoTClient(endpoint string) *DoTClient {
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{},
	}
	return &DoTClient{
		endpoint: endpoint,
		conn:     NewPipeline(endpoint, client),
	}
}

// Resolve a DNS query.
func (d *DoTClient) Resolve(q *dns.Msg) (*dns.Msg, error) {
	return d.conn.Resolve(q)
}

func (d *DoTClient) String() string {
	return fmt.Sprintf("DoT(%s)", d.endpoint)
}
