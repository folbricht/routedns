package rdns

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	quic "github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
)

const (
	DOQNoError = 0x00
)

// DoQClient is a DNS-over-QUIC resolver.
type DoQClient struct {
	DoQClientOptions
	id       string
	endpoint string
	requests chan *request
	log      *logrus.Entry
	metrics  *ListenerMetrics

	connection doqConnection
}

// DoQClientOptions contains options used by the DNS-over-QUIC resolver.
type DoQClientOptions struct {
	// Bootstrap address - IP to use for the service instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	TLSConfig *tls.Config
}

var _ Resolver = &DoQClient{}

// NewDoQClient instantiates a new DNS-over-QUIC resolver.
func NewDoQClient(id, endpoint string, opt DoQClientOptions) (*DoQClient, error) {
	if err := validEndpoint(endpoint); err != nil {
		return nil, err
	}
	var tlsConfig *tls.Config
	if opt.TLSConfig == nil {
		tlsConfig = new(tls.Config)
	} else {
		tlsConfig = opt.TLSConfig.Clone()
	}
	tlsConfig.NextProtos = []string{"doq"}
	lAddr := net.IPv4zero
	if opt.LocalAddr != nil {
		lAddr = opt.LocalAddr
	}
	// If a bootstrap address was provided, we need to use the IP for the connection but the
	// hostname in the TLS handshake. The library doesn't support custom dialers, so
	// instead set the ServerName in the TLS config to the name in the endpoint config, and
	// replace the name in the endpoint with the bootstrap IP.
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse dot endpoint '%s'", endpoint)
	}
	if opt.BootstrapAddr != "" {
		tlsConfig.ServerName = host
		endpoint = net.JoinHostPort(opt.BootstrapAddr, port)
	}
	log := Log.WithFields(logrus.Fields{"protocol": "doq", "endpoint": endpoint})
	return &DoQClient{
		id:               id,
		endpoint:         endpoint,
		DoQClientOptions: opt,
		requests:         make(chan *request),
		log:              log,
		connection: doqConnection{
			hostname:  host,
			endpoint:  endpoint,
			lAddr:     lAddr,
			tlsConfig: tlsConfig,
			config: &quic.Config{
				TokenStore: quic.NewLRUTokenStore(10, 10),
			},
			pool: new(udpConnPool),
			log:  log,
		},
		metrics: NewListenerMetrics("client", id),
	}, nil
}

// Resolve a DNS query.
func (d *DoQClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	logger(d.id, q, ci).WithFields(logrus.Fields{
		"resolver": d.endpoint,
		"protocol": "doq",
	}).Debug("querying upstream resolver")

	d.metrics.query.Add(1)

	// Sending a edns-tcp-keepalive EDNS(0) option over DoQ is an error. Filter it out.
	edns0 := q.IsEdns0()
	if edns0 != nil {
		newOpt := make([]dns.EDNS0, 0, len(edns0.Option))
		for _, opt := range edns0.Option {
			if opt.Option() == dns.EDNS0TCPKEEPALIVE {
				continue
			}
			newOpt = append(newOpt, opt)
		}
		edns0.Option = newOpt
	}

	// When sending queries over a DoQ, the DNS Message ID MUST be set to zero. Don't forget
	// to restore the ID in the original query, it could be needed for error responses further
	// up
	id := q.Id
	q.Id = 0
	defer func() { q.Id = id }()

	// Encode the query
	p, err := q.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}

	// Add a length prefix
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)

	// Get a new stream in the connection
	stream, err := d.connection.getStream()
	if err != nil {
		d.metrics.err.Add("getstream", 1)
		return nil, err
	}

	// Write the query into the stream and close is. Only one stream per query/response
	_ = stream.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err = stream.Write(p); err != nil {
		d.metrics.err.Add("write", 1)
		return nil, err
	}
	if err = stream.Close(); err != nil {
		d.metrics.err.Add("close", 1)
		return nil, err
	}

	_ = stream.SetReadDeadline(time.Now().Add(time.Second))

	// DoQ requires a length prefix, like TCP
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		d.metrics.err.Add("read", 1)
		return nil, err
	}

	// Read the response
	b = make([]byte, length)
	if _, err = io.ReadFull(stream, b); err != nil {
		d.metrics.err.Add("read", 1)
		return nil, err
	}

	// Decode the response and restore the ID
	a := new(dns.Msg)
	err = a.Unpack(b)
	a.Id = id

	// Receiving a edns-tcp-keepalive EDNS(0) option is a fatal error according to the RFC
	edns0 = a.IsEdns0()
	if edns0 != nil {
		for _, opt := range edns0.Option {
			if opt.Option() == dns.EDNS0TCPKEEPALIVE {
				d.log.Error("received edns-tcp-keepalive from doq server, aborting")
				d.metrics.err.Add("keepalive", 1)
				return nil, errors.New("received edns-tcp-keepalive over doq server")
			}
		}
	}
	d.metrics.response.Add(rCode(a), 1)

	return a, err
}

func (d *DoQClient) String() string {
	return d.id
}

type doqConnection struct {
	hostname  string
	endpoint  string
	lAddr     net.IP
	tlsConfig *tls.Config
	config    *quic.Config
	log       *logrus.Entry
	pool      *udpConnPool

	connection quic.Connection

	mu sync.Mutex
}

func (s *doqConnection) getStream() (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If we don't have a connection yet, make one
	if s.connection == nil {
		var err error
		s.connection, err = quicDial(s.hostname, s.endpoint, s.lAddr, s.tlsConfig, s.config, s.pool)
		if err != nil {
			s.log.WithError(err).Error("failed to open connection")
			return nil, err
		}
	}

	stream, err := s.connection.OpenStream()
	if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
		// Try to open a new connection
		_ = s.connection.CloseWithError(DOQNoError, "")
		s.connection, err = quicDial(s.hostname, s.endpoint, s.lAddr, s.tlsConfig, s.config, s.pool)
		if err != nil {
			s.log.WithError(err).Error("failed to open connection")
			return nil, err
		}
		stream, err = s.connection.OpenStream()
		if err != nil {
			s.log.WithError(err).Error("failed to open stream")
			return nil, err
		}
	}
	return stream, err
}
