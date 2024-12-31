package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"expvar"
	"io"
	"net"
	"time"

	"log/slog"

	"github.com/miekg/dns"
	quic "github.com/quic-go/quic-go"
)

// DoQListener is a DNS listener/server for QUIC.
type DoQListener struct {
	id      string
	addr    string
	r       Resolver
	opt     DoQListenerOptions
	ln      *quic.EarlyListener
	log     *slog.Logger
	metrics *DoQListenerMetrics
}

var _ Listener = &DoQListener{}

// DoQListenerOptions contains options used by the QUIC server.
type DoQListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

type DoQListenerMetrics struct {
	ListenerMetrics

	// Count of connections initiated.
	connection *expvar.Int
	// Count of streams seen in all connections.
	stream *expvar.Int
}

func NewDoQListenerMetrics(id string) *DoQListenerMetrics {
	return &DoQListenerMetrics{
		ListenerMetrics: ListenerMetrics{
			query:    getVarInt("listener", id, "query"),
			response: getVarMap("listener", id, "response"),
			drop:     getVarInt("listener", id, "drop"),
			err:      getVarMap("listener", id, "error"),
		},
		connection: getVarInt("listener", id, "session"),
		stream:     getVarInt("listener", id, "stream"),
	}
}

// NewQuicListener returns an instance of a QUIC listener.
func NewQUICListener(id, addr string, opt DoQListenerOptions, resolver Resolver) *DoQListener {
	if opt.TLSConfig == nil {
		opt.TLSConfig = new(tls.Config)
	}
	opt.TLSConfig.NextProtos = []string{"doq"}
	l := &DoQListener{
		id:      id,
		addr:    addr,
		r:       resolver,
		opt:     opt,
		log:     Log.With("id", id, "protocol", "doq", "addr", addr),
		metrics: NewDoQListenerMetrics(id),
	}
	return l
}

// Start the QUIC server.
func (s DoQListener) Start() error {
	var err error
	s.ln, err = quic.ListenAddrEarly(s.addr, s.opt.TLSConfig, &quic.Config{
		Allow0RTT:      true,
		MaxIdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		return err
	}
	s.log.Info("starting listener")

	for {
		connection, err := s.ln.Accept(context.Background())
		if err != nil {
			s.log.Warn("failed to accept", "error", err)
			continue
		}
		s.log.Debug("started connection")
		go func() { s.handleConnection(connection) }()
	}
}

// Stop the server.
func (s DoQListener) Stop() error {
	s.log.Info("stopping listener", slog.Group("details", slog.String("protocol", "quic"), slog.String("addr", s.addr)))
	return s.ln.Close()
}

func (s DoQListener) handleConnection(connection quic.Connection) {
	tlsServerName := connection.ConnectionState().TLS.ServerName

	ci := ClientInfo{
		Listener:      s.id,
		TLSServerName: tlsServerName,
	}
	switch addr := connection.RemoteAddr().(type) {
	case *net.TCPAddr:
		ci.SourceIP = addr.IP
	case *net.UDPAddr:
		ci.SourceIP = addr.IP
	}
	log := s.log.With("client", connection.RemoteAddr())

	if !isAllowed(s.opt.AllowedNet, ci.SourceIP) {
		log.Debug("rejecting incoming connection")
		s.metrics.drop.Add(1)
		return
	}
	log.Debug("accepting incoming connection")
	s.metrics.connection.Add(1)

	for {
		stream, err := connection.AcceptStream(context.Background())
		if err != nil {
			break
		}
		log.With("stream", stream.StreamID()).Debug("opening stream")
		go func() {
			s.handleStream(stream, log, ci)
			log.With("stream", stream.StreamID()).Debug("closing stream")
		}()
	}
}

func (s DoQListener) handleStream(stream quic.Stream, log *slog.Logger, ci ClientInfo) {
	// DNS over QUIC uses one stream per query/response.
	defer stream.Close()
	s.metrics.stream.Add(1)

	// DoQ requires a length prefix, like TCP
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		s.metrics.err.Add("read", 1)
		log.Error("failed to read query", "error", err)
		return
	}

	// Read the raw query
	b := make([]byte, length)
	_ = stream.SetReadDeadline(time.Now().Add(time.Second)) // TODO: configurable timeout
	if _, err := io.ReadFull(stream, b); err != nil {
		s.metrics.err.Add("read", 1)
		log.Error("failed to read query", "error", err)
		return
	}

	// Decode the query
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		s.metrics.err.Add("unpack", 1)
		log.Error("failed to decode query", "error", err)
		return
	}
	log = log.With("qname", qName(q))
	log.Debug("received query")
	s.metrics.query.Add(1)

	// Receiving a edns-tcp-keepalive EDNS(0) option is a fatal error according to the RFC
	edns0 := q.IsEdns0()
	if edns0 != nil {
		for _, opt := range edns0.Option {
			if opt.Option() == dns.EDNS0TCPKEEPALIVE {
				log.Error("received edns-tcp-keepalive, aborting")
				s.metrics.err.Add("keepalive", 1)
				return
			}
		}
	}

	// Resolve the query using the next hop
	a, err := s.r.Resolve(q, ci)
	if err != nil {
		log.Error("failed to resolve", "error", err)
		a = new(dns.Msg)
		a.SetRcode(q, dns.RcodeServerFailure)
	}

	p, err := a.Pack()
	if err != nil {
		log.Error("failed to encode response", "error", err)
		s.metrics.err.Add("encode", 1)
		return
	}

	// Add a length prefix
	out := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(out, uint16(len(p)))
	copy(out[2:], p)

	// Send the response
	_ = stream.SetWriteDeadline(time.Now().Add(time.Second)) // TODO: configurable timeout
	if _, err = stream.Write(out); err != nil {
		s.metrics.err.Add("send", 1)
		log.Error("failed to send response", "error", err)
	}
	s.metrics.response.Add(rCode(a), 1)
}

func (s DoQListener) String() string {
	return s.id
}
