package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"log/slog"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	quic "github.com/quic-go/quic-go"
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
	log      *slog.Logger
	metrics  *ListenerMetrics

	connection quicConnection
}

// DoQClientOptions contains options used by the DNS-over-QUIC resolver.
type DoQClientOptions struct {
	// Bootstrap address - IP to use for the service instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr    net.IP
	TLSConfig    *tls.Config
	QueryTimeout time.Duration
	Use0RTT      bool
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
		endpoint = net.JoinHostPort(opt.BootstrapAddr, port)
	}

	// quic-go requires the ServerName be set explicitly
	tlsConfig.ServerName = host

	// enable TLS session caching for session resumption and 0-RTT
	if opt.Use0RTT {
		tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(100)
	}

	if opt.QueryTimeout == 0 {
		opt.QueryTimeout = defaultQueryTimeout
	}
	log := Log.With(
		"protocol", "doq",
		"endpoint", endpoint,
	)
	return &DoQClient{
		id:               id,
		endpoint:         endpoint,
		DoQClientOptions: opt,
		requests:         make(chan *request),
		log:              log,
		connection: quicConnection{
			hostname:  host,
			lAddr:     lAddr,
			tlsConfig: tlsConfig,
			config: &quic.Config{
				TokenStore:           quic.NewLRUTokenStore(10, 10),
				HandshakeIdleTimeout: opt.QueryTimeout,
			},
			Use0RTT: opt.Use0RTT,
		},
		metrics: NewListenerMetrics("client", id),
	}, nil
}

// Resolve a DNS query.
func (d *DoQClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	Log.Debug("querying upstream resolver", slog.Group("details", slog.String("id", d.id), slog.String("resolver", d.endpoint), slog.String("protocol", "doq"), slog.String("qname", qName(q)), slog.String("qtype", qType(q))))

	d.metrics.query.Add(1)

	// When sending queries over a DoQ, the DNS Message ID MUST be set to zero.
	// Make a deep copy because if there are multiple upstreams second
	// and subsequent replies downstream will have 0 for an Id (by default a
	// query is shared with all upstreams)
	qc := q.Copy()
	qc.Id = 0

	// Sending a edns-tcp-keepalive EDNS(0) option over DoQ is an error. Filter it out.
	edns0 := qc.IsEdns0()
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

	deadlineTime := time.Now().Add(d.DoQClientOptions.QueryTimeout)

	// Encode the query
	p, err := qc.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}

	// Add a length prefix
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)

	// Get a new stream in the connection
	stream, err := d.connection.getStream(d.endpoint, d.log)
	if err != nil {
		d.metrics.err.Add("getstream", 1)
		return nil, err
	}

	// Write the query into the stream and close it. Only one stream per query/response
	_ = stream.SetWriteDeadline(deadlineTime)
	if _, err = stream.Write(b); err != nil {
		d.metrics.err.Add("write", 1)
		return nil, err
	}
	if err = stream.Close(); err != nil {
		d.metrics.err.Add("close", 1)
		return nil, err
	}

	_ = stream.SetReadDeadline(deadlineTime)

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
	a.Id = q.Id

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

func (s *quicConnection) getStream(endpoint string, log *slog.Logger) (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If we don't have a connection yet, make one
	if s.EarlyConnection == nil {
		var err error
		s.EarlyConnection, s.udpConn, err = quicDial(context.TODO(), endpoint, s.lAddr, s.tlsConfig, s.config, s.Use0RTT)
		if err != nil {
			log.Error("failed to open connection",
				"hostname", s.hostname,
				"error", err,
			)
			return nil, err
		}
		s.rAddr = endpoint
	}

	// If we can't get a stream then restart the connection and try again once
	stream, err := s.EarlyConnection.OpenStream()
	if err != nil {
		log.Debug("temporary fail when trying to open stream, attempting new connection",
			"error", err,
		)
		if err = quicRestart(s); err != nil {
			log.Error("failed to open connection", "hostname", s.hostname, "error", err)
			return nil, err
		}
		stream, err = s.EarlyConnection.OpenStream()
		if err != nil {
			log.Error("failed to open stream",
				"error", err,
			)
		}
	}
	return stream, err
}
