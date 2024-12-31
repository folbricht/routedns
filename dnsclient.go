package rdns

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"log/slog"

	"github.com/miekg/dns"
)

// DNSClient represents a simple DNS resolver for UDP or TCP.
type DNSClient struct {
	id       string
	endpoint string
	net      string
	pipeline *Pipeline // Pipeline also provides operation metrics.
	opt      DNSClientOptions
}

type Dialer interface {
	Dial(net string, address string) (net.Conn, error)
}

type DNSClientOptions struct {
	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	// Sets the EDNS0 UDP size for all queries sent upstream. If set to 0, queries
	// are not changed.
	UDPSize uint16

	QueryTimeout time.Duration

	// Optional dialer, e.g. proxy
	Dialer Dialer
}

var _ Resolver = &DNSClient{}

// NewDNSClient returns a new instance of DNSClient which is a plain DNS resolver
// that supports pipelining over a single connection.
func NewDNSClient(id, endpoint, network string, opt DNSClientOptions) (*DNSClient, error) {
	if err := validEndpoint(endpoint); err != nil {
		return nil, err
	}
	client := GenericDNSClient{
		Net:       network,
		Dialer:    opt.Dialer,
		TLSConfig: &tls.Config{},
		LocalAddr: opt.LocalAddr,
		Timeout:   opt.QueryTimeout,
	}
	return &DNSClient{
		id:       id,
		net:      network,
		endpoint: endpoint,
		pipeline: NewPipeline(id, endpoint, client, opt.QueryTimeout),
		opt:      opt,
	}, nil
}

// Resolve a DNS query.
func (d *DNSClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	// Packing a message is not always a read-only operation, make a copy
	q = q.Copy()
	log := logger(d.id, q, ci)
	log.Debug("querying upstream resolver",
		slog.String("resolver", d.endpoint),
		slog.String("protocol", d.net),
	)

	q = setUDPSize(q, d.opt.UDPSize)

	// Remove padding before sending over the wire in plain
	stripPadding(q)
	return d.pipeline.Resolve(q)
}

func (d *DNSClient) String() string {
	return d.id
}

// GenericDNSClient is a workaround for dns.Client not supporting custom dialers
// (only *net.Dialer) which prevents the use of proxies. It implements the same
// Dial functionality, while supporting custom dialers.
type GenericDNSClient struct {
	Dialer    Dialer
	Net       string
	TLSConfig *tls.Config
	LocalAddr net.IP
	Timeout   time.Duration
}

func (d GenericDNSClient) Dial(address string) (*dns.Conn, error) {
	network := d.Net

	// If we want TLS on it, perform the handshake
	useTLS := strings.HasPrefix(network, "tcp") && strings.HasSuffix(network, "-tls")
	network = strings.TrimSuffix(network, "-tls")

	dialer := d.Dialer
	if dialer == nil {
		// Use a custom dialer if a local address was provided
		if d.LocalAddr != nil {
			switch network {
			case "tcp":
				dialer = &net.Dialer{LocalAddr: &net.TCPAddr{IP: d.LocalAddr}, Timeout: d.Timeout}
			case "udp":
				dialer = &net.Dialer{LocalAddr: &net.UDPAddr{IP: d.LocalAddr}, Timeout: d.Timeout}
			}
		} else {
			dialer = &net.Dialer{}
		}
	}

	var (
		conn = &dns.Conn{
			UDPSize: 4096,
		}
		err error
	)
	// Open a raw connection
	conn.Conn, err = dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Trick dns.Conn.ReadMsg() into thinking this is a packet connection (udp) so it
	// correctly handles any length-prefixes
	if network == "udp" {
		conn.Conn = packetConnWrapper{conn.Conn}
	}

	if useTLS {
		hostname, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		tlsConfig := d.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		// Make sure a servername is set
		if tlsConfig.ServerName == "" {
			c := tlsConfig.Clone()
			c.ServerName = hostname
			tlsConfig = c
		}
		conn.Conn = tls.Client(conn.Conn, tlsConfig)
	}

	return conn, nil
}

// packetConnWrapper is another workaround for dns.Conn which checks if the Conn
// it has implements net.PacketConn and based on that distinguishes between a UDP
// connection (don't need length prefix) and TCP (need length prefix). This doesn't
// actually implement these, but dns.Conn.ReadMsg() doesn't use them either.
type packetConnWrapper struct {
	net.Conn
}

var _ net.PacketConn = packetConnWrapper{}

func (c packetConnWrapper) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	panic("not implemented")
}

func (c packetConnWrapper) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	panic("not implemented")
}
