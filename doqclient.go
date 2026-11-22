package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"log/slog"

	"github.com/miekg/dns"
	quic "github.com/quic-go/quic-go"
)

const (
	DOQNoError          = 0x00
	DOQRequestCancelled = 0x03
)

// DoQClient is a DNS-over-QUIC resolver.
type DoQClient struct {
	DoQClientOptions
	id       string
	endpoint string
	requests chan *request
	log      *slog.Logger
	metrics  *listenerMetrics

	connection   *quicConnection
	connectionV4 *quicConnection // IPv4-specific connection, used in dual-stack mode
	connectionV6 *quicConnection // IPv6-specific connection, used in dual-stack mode
}

// DoQClientOptions contains options used by the DNS-over-QUIC resolver.
type DoQClientOptions struct {
	// Bootstrap address - IP to use for the service instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr   net.IP
	LocalAddrV4 net.IP
	LocalAddrV6 net.IP

	TLSConfig    *tls.Config
	QueryTimeout time.Duration

	// IdleTimeout sets the QUIC MaxIdleTimeout. Zero uses the library default.
	// The effective value is the lower of this and the server's.
	IdleTimeout time.Duration
	Use0RTT     bool

	// Linux network namespace for outbound connections.
	NetNS *NetNS

	// Linux socket options for fwmark and interface binding.
	SocketOptions SocketOptions
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
	// If a bootstrap address was provided, we need to use the IP for the connection but the
	// hostname in the TLS handshake. The library doesn't support custom dialers, so
	// instead set the ServerName in the TLS config to the name in the endpoint config, and
	// replace the name in the endpoint with the bootstrap IP.
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse doq endpoint '%s': %w", endpoint, err)
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
		"id", id,
		"upstream-protocol", "doq",
		"endpoint", endpoint,
	)
	config := &quic.Config{
		TokenStore:           quic.NewLRUTokenStore(10, 10),
		HandshakeIdleTimeout: opt.QueryTimeout,
	}
	if opt.IdleTimeout > 0 {
		config.MaxIdleTimeout = opt.IdleTimeout
	}

	client := &DoQClient{
		id:               id,
		endpoint:         endpoint,
		DoQClientOptions: opt,
		requests:         make(chan *request),
		log:              log,
		metrics:          newListenerMetrics("client", id),
	}

	// When both V4 and V6 local addresses are specified, create two QUIC connections
	// since a UDP socket bound to an IPv4 address cannot reach IPv6 endpoints and vice versa.
	if opt.LocalAddrV4 != nil && opt.LocalAddrV6 != nil {
		qConn4, err := newQuicConnection(opt.LocalAddrV4, tlsConfig, config, opt.Use0RTT, opt.NetNS, opt.SocketOptions)
		if err != nil {
			return nil, err
		}
		qConn6, err := newQuicConnection(opt.LocalAddrV6, tlsConfig, config, opt.Use0RTT, opt.NetNS, opt.SocketOptions)
		if err != nil {
			return nil, err
		}
		client.connectionV4 = qConn4
		client.connectionV6 = qConn6
	} else {
		lAddr := net.IPv4zero
		if opt.LocalAddr != nil {
			lAddr = opt.LocalAddr
		}
		if opt.LocalAddrV4 != nil {
			lAddr = opt.LocalAddrV4
		}
		if opt.LocalAddrV6 != nil {
			lAddr = opt.LocalAddrV6
		}
		qConn, err := newQuicConnection(lAddr, tlsConfig, config, opt.Use0RTT, opt.NetNS, opt.SocketOptions)
		if err != nil {
			return nil, err
		}
		client.connection = qConn
	}

	return client, nil
}

// Resolve a DNS query.
func (d *DoQClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	logger(d.id, q, ci).Debug("querying upstream resolver",
		"resolver", d.endpoint,
		"upstream-protocol", "doq",
	)

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
	ctx, cancel := context.WithDeadline(context.Background(), deadlineTime)
	defer cancel()

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

	var local net.IP
	if d.connection != nil {
		local = d.connection.lAddr
	}
	rAddr, err := resolveUDPAddr(ctx, d.endpoint, local)
	if err != nil {
		d.metrics.err.Add("resolve", 1)
		return nil, err
	}

	// Select the right connection for dual-stack
	conn := d.connection
	if conn == nil {
		conn = d.connectionV4
		if rAddr.IP.To4() == nil {
			conn = d.connectionV6
		}
	}
	replaySafe := isReplayableOpcode(qc.Opcode)
	resp, stage, err := d.exchange(ctx, conn, rAddr, b, replaySafe)
	if errors.Is(err, quic.Err0RTTRejected) {
		// The server discarded the query along with the rest of the 0-RTT
		// data, so it is safe to send again. After the handshake this time:
		// the query may move off a full connection onto a new one, which
		// could reject 0-RTT data too.
		resp, stage, err = d.exchange(ctx, conn, rAddr, b, false)
	}
	if err != nil {
		d.metrics.err.Add(stage, 1)
		return nil, err
	}

	// Decode the response and restore the ID
	a := new(dns.Msg)
	if err := a.Unpack(resp); err != nil {
		d.metrics.err.Add("unpack", 1)
		return nil, err
	}
	a.Id = q.Id

	// The QUIC stream proves which stream carried the response, not that the DNS
	// message in it answers the question that was asked.
	if err := validateResponseQuestion(q, a); err != nil {
		d.metrics.err.Add("question", 1)
		return nil, err
	}

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

	return a, nil
}

func (d *DoQClient) String() string {
	return d.id
}

// exchange sends the length-prefixed query on a new stream and returns the
// response without its prefix. On failure it also returns the stage that
// failed, for the error metric.
func (d *DoQClient) exchange(ctx context.Context, conn *quicConnection, rAddr *net.UDPAddr, query []byte, replaySafe bool) (resp []byte, stage string, err error) {
	stream, early, err := conn.getStream(ctx, rAddr, replaySafe, d.log)
	if err != nil {
		return nil, "getstream", err
	}
	defer func() {
		// Tell the server to drop a query that failed, which frees its stream
		// for another one. Not for a stream opened before the handshake
		// completed: if the server rejects 0-RTT, quic-go reuses its ID for a
		// later stream, and since this one had finished writing, CancelWrite
		// would still send a RESET_STREAM, which the server applies to that
		// later stream.
		if err != nil && !early {
			stream.CancelWrite(DOQRequestCancelled)
			stream.CancelRead(DOQRequestCancelled)
		}
	}()
	deadline, _ := ctx.Deadline()

	// Write the query into the stream and close it. Only one stream per query/response
	_ = stream.SetWriteDeadline(deadline)
	if _, err = stream.Write(query); err != nil {
		return nil, "write", err
	}
	if err = stream.Close(); err != nil {
		return nil, "close", err
	}

	_ = stream.SetReadDeadline(deadline)

	// DoQ requires a length prefix, like TCP
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		return nil, "read", err
	}

	// Read the response
	b := make([]byte, length)
	if _, err = io.ReadFull(stream, b); err != nil {
		return nil, "read", err
	}
	return b, "", nil
}

// resolveUDPAddr is net.ResolveUDPAddr bounded by ctx. Like it, it picks an
// IPv4 address when the name has both. A socket bound to a specific local
// address can only reach upstreams of the same family though, so with one of
// those only an address of that family will do.
func resolveUDPAddr(ctx context.Context, endpoint string, local net.IP) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	portNum, err := net.DefaultResolver.LookupPort(ctx, "udp", port)
	if err != nil {
		return nil, err
	}
	// LookupIPAddr rather than LookupNetIP, which drops the zone of a
	// link-local literal.
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
	}
	bound := local != nil && !local.IsUnspecified()
	want6 := bound && local.To4() == nil
	addr := addrs[0]
	for _, a := range addrs {
		if (a.IP.To4() == nil) == want6 {
			addr = a
			break
		}
	}
	if bound && (addr.IP.To4() == nil) != want6 {
		family := "IPv4"
		if want6 {
			family = "IPv6"
		}
		return nil, &net.AddrError{Err: "no " + family + " address for a connection bound to an " + family + " address", Addr: host}
	}
	return &net.UDPAddr{IP: addr.IP, Port: portNum, Zone: addr.Zone}, nil
}

// QUIC connection that automatically restarts when it's used after having
// timed out. Needed since the quic.Transport doesn't have any connection
// management and timed out connections aren't restarted. This one uses
// EarlyConnection so we can use 0-RTT if the server supports it (lower
// latency)
type quicConnection struct {
	lAddr     net.IP
	tlsConfig *tls.Config
	config    *quic.Config
	udpConn   *net.UDPConn
	dialFunc  func(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error)

	mu       sync.Mutex
	conn     *quic.Conn
	dial     *quicDial    // the attempt in progress, if any
	replaced []*quic.Conn // connections replaced while still open, oldest first
}

// doqMaxReplaced is how many connections a socket keeps open after replacing
// them at the server's stream limit. They finish the queries in flight on
// them and take new ones when the current connection is full. Replacing one
// more closes the oldest at once, failing any query still on it.
const doqMaxReplaced = 4

// quicDial is one connection attempt, shared by every query that needs a
// connection while it runs. conn and err are set before done is closed.
type quicDial struct {
	done chan struct{}
	conn *quic.Conn
	err  error
}

func newQuicConnection(lAddr net.IP, tlsConfig *tls.Config, config *quic.Config, use0RTT bool, netns *NetNS, sockOpts SocketOptions) (*quicConnection, error) {
	// Initialize the local UDP connection, it'll be re-used for all connections
	udpConn, err := ListenUDPInNetNS(context.Background(), netns, "udp", &net.UDPAddr{IP: lAddr, Port: 0}, sockOpts)
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

// getStream opens a new stream, dialling or restarting the connection if
// needed. Callers about to write something that must not be replayed pass
// replaySafe=false, and the stream is then not handed out until the
// connection's handshake has completed. early reports a stream opened before
// the handshake completed. ctx bounds every wait in here.
func (s *quicConnection) getStream(ctx context.Context, rAddr *net.UDPAddr, replaySafe bool, log *slog.Logger) (stream *quic.Stream, early bool, err error) {
	conn, err := s.connection(ctx, rAddr, nil, log)
	if err != nil {
		return nil, false, err
	}
	stream, early, err = openStream(ctx, conn, replaySafe)
	if err == nil || ctx.Err() != nil {
		return stream, early, err
	}

	// A connection replaced when it was full may have free streams again.
	// Only one past its handshake, which no query should wait for here.
	if errors.As(err, new(*quic.StreamLimitReachedError)) {
		s.mu.Lock()
		replaced := slices.Clone(s.replaced)
		s.mu.Unlock()
		for _, c := range replaced {
			select {
			case <-c.HandshakeComplete():
				if stream, early, err := openStream(ctx, c, replaySafe); err == nil {
					return stream, early, nil
				}
			default:
			}
		}
	}

	// If we can't get a stream then restart the connection and try again once
	log.Debug("temporary fail when trying to open stream, attempting new connection",
		"error", err,
	)
	if conn, err = s.connection(ctx, rAddr, conn, log); err != nil {
		return nil, false, err
	}
	stream, early, err = openStream(ctx, conn, replaySafe)
	if err != nil {
		log.Warn("failed to open stream",
			"error", err,
		)
	}
	return stream, early, err
}

// connection returns the current QUIC connection, dialling one if there is
// none or the caller found the current one broken and passes it as stale. The
// dial runs in the background and is shared by every caller that arrives while
// it is in progress. ctx bounds only the caller's wait: a connection outlives
// the query that asked for it, so an attempt keeps going after its callers
// gave up and serves the queries after them.
func (s *quicConnection) connection(ctx context.Context, rAddr *net.UDPAddr, stale *quic.Conn, log *slog.Logger) (*quic.Conn, error) {
	s.mu.Lock()
	dial := s.dial
	var evicted *quic.Conn
	if dial == nil {
		if s.conn != nil && s.conn != stale {
			conn := s.conn
			s.mu.Unlock()
			return conn, nil
		}
		// Keep the connection if it is open, which means it is only full.
		// Those that have closed since give up their place.
		if s.conn != nil {
			s.replaced = append(s.replaced, s.conn)
		}
		s.conn = nil
		s.replaced = slices.DeleteFunc(s.replaced, func(c *quic.Conn) bool { return c.Context().Err() != nil })
		if len(s.replaced) > doqMaxReplaced {
			evicted = s.replaced[0]
			s.replaced = slices.Delete(s.replaced, 0, 1)
		}
		dial = &quicDial{done: make(chan struct{})}
		s.dial = dial
		go s.runDial(dial, rAddr, log)
	}
	s.mu.Unlock()

	// Closing waits for the connection to shut down, which no query should
	// have to sit through.
	if evicted != nil {
		go func() { _ = evicted.CloseWithError(DOQNoError, "") }()
	}

	select {
	case <-dial.done:
		return dial.conn, dial.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *quicConnection) runDial(dial *quicDial, rAddr *net.UDPAddr, log *slog.Logger) {
	dial.conn, dial.err = s.dialFunc(context.Background(), rAddr, s.tlsConfig, s.config)
	if dial.err != nil {
		log.Warn("failed to open connection",
			"remote", rAddr.String(),
			"local", s.lAddr.String(),
			"error", dial.err,
		)
	}
	s.mu.Lock()
	s.conn, s.dial = dial.conn, nil
	s.mu.Unlock()
	close(dial.done)
}

// openStream opens a stream on conn, first waiting for the handshake when the
// caller's data must not be replayed, or when the server rejected 0-RTT and
// the connection is only usable once the handshake completes. early reports
// that the handshake hadn't completed when the stream was opened.
func openStream(ctx context.Context, conn *quic.Conn, replaySafe bool) (stream *quic.Stream, early bool, err error) {
	if err := awaitReplaySafe(ctx, conn, replaySafe); err != nil {
		return nil, false, err
	}
	select {
	case <-conn.HandshakeComplete():
	default:
		early = true
	}
	stream, err = conn.OpenStream()
	if errors.Is(err, quic.Err0RTTRejected) {
		if _, err := conn.NextConnection(ctx); err != nil {
			return nil, false, err
		}
		early = false
		stream, err = conn.OpenStream()
	}
	return stream, early, err
}

// awaitReplaySafe blocks until nothing written to conn can go out as
// replayable 0-RTT data, either because the handshake completed or because the
// connection is gone. A dead connection is left for the caller's OpenStream to
// discover and restart; failing here instead would break the retry. It returns
// at once when the caller's data is replay-safe anyway, and for connections
// dialled without 0-RTT, which are only handed out post-handshake.
func awaitReplaySafe(ctx context.Context, conn *quic.Conn, replaySafe bool) error {
	if replaySafe {
		return nil
	}
	select {
	case <-conn.HandshakeComplete():
	case <-conn.Context().Done():
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
