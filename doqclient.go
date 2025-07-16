package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
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

	connection *quicConnection
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
	config := &quic.Config{
		TokenStore:           quic.NewLRUTokenStore(10, 10),
		HandshakeIdleTimeout: opt.QueryTimeout,
	}
	qConn, err := newQuicConnection(lAddr, tlsConfig, config, opt.Use0RTT)
	if err != nil {
		return nil, err
	}
	return &DoQClient{
		id:               id,
		endpoint:         endpoint,
		DoQClientOptions: opt,
		requests:         make(chan *request),
		log:              log,
		connection:       qConn,
		metrics:          NewListenerMetrics("client", id),
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
				d.log.Warn("received edns-tcp-keepalive from doq server, aborting")
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

// QUIC connection that automatically restarts when it's used after having
// timed out. Needed since the quic.Transport doesn't have any connection
// management and timed out connections aren't restarted. This one uses
// EarlyConnection so we can use 0-RTT if the server supports it (lower
// latency)
type quicConnection struct {
	*quic.Conn

	lAddr     net.IP
	tlsConfig *tls.Config
	config    *quic.Config
	mu        sync.Mutex
	udpConn   *net.UDPConn
	dialFunc  func(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error)
}

func newQuicConnection(lAddr net.IP, tlsConfig *tls.Config, config *quic.Config, use0RTT bool) (*quicConnection, error) {
	// Initialize the local UDP connection, it'll be re-used for all connections
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr, Port: 0})
	if err != nil {
		Log.Error("couldn't listen on UDP socket on local address", "error", err, "local", lAddr.String())
		return nil, err
	}
	quicTransport := &quic.Transport{Conn: udpConn}

	dialFunc := quicTransport.Dial
	if use0RTT {
		dialFunc = quicTransport.DialEarly
	}

	return &quicConnection{
		lAddr:     lAddr,
		tlsConfig: tlsConfig,
		config:    config,
		udpConn:   udpConn,
		dialFunc:  dialFunc,
	}, nil
}

func (s *quicConnection) getStream(endpoint string, log *slog.Logger) (*quic.Stream, error) {
	rAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// If we don't have a connection yet, make one
	if s.Conn == nil {
		var err error
		s.Conn, err = s.dialFunc(context.Background(), rAddr, s.tlsConfig, s.config)
		if err != nil {
			log.Warn("failed to open connection",
				"hostname", endpoint,
				"error", err,
			)
			return nil, err
		}
	}

	// If we can't get a stream then restart the connection and try again once
	stream, err := s.Conn.OpenStream()
	if err != nil {
		log.Debug("temporary fail when trying to open stream, attempting new connection",
			"error", err,
		)
		if err = s.restart(rAddr); err != nil {
			log.Warn("failed to open connection", "hostname", endpoint, "error", err)
			return nil, err
		}
		stream, err = s.Conn.OpenStream()
		if err != nil {
			log.Warn("failed to open stream",
				"error", err,
			)
		}
	}
	return stream, err
}

// Try to open a new connection. This function should be called with the mutex
// locked.
func (s *quicConnection) restart(rAddr *net.UDPAddr) error {
	_ = s.Conn.CloseWithError(DOQNoError, "")

	Log.Debug("attempt reconnect", slog.String("protocol", "quic"),
		slog.String("local", s.lAddr.String()),
		slog.String("remote", rAddr.String()),
	)
	conn, err := s.dialFunc(context.TODO(), rAddr, s.tlsConfig, s.config)
	if err != nil {
		Log.Warn("couldn't restart quic connection", slog.Group("details", slog.String("protocol", "quic"), slog.String("remote", rAddr.String()), slog.String("local", s.lAddr.String())), "error", err)
		return err
	}
	Log.Debug("restarted quic connection", slog.Group("details", slog.String("protocol", "quic"), slog.String("remote", rAddr.String()), slog.String("local", s.lAddr.String())))

	s.Conn = conn
	return nil
}
