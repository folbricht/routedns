package rdns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"log/slog"

	"github.com/miekg/dns"
	"github.com/pion/dtls/v3"
)

// DTLSListener is a DNS listener/server for DNS-over-DTLS.
type DTLSListener struct {
	*dns.Server
	id string

	opt DTLSListenerOptions
}

var _ Listener = &DTLSListener{}

// DTLSListenerOptions contains options used by the DNS-over-DTLS server.
type DTLSListenerOptions struct {
	ListenOptions

	DTLSConfig *dtls.Config
}

// NewDTLSListener returns an instance of a DNS-over-DTLS listener.
func NewDTLSListener(id, addr string, opt DTLSListenerOptions, resolver Resolver) *DTLSListener {
	return &DTLSListener{
		id: id,
		Server: &dns.Server{
			Addr:    addr,
			Handler: listenHandler(id, "dtls", addr, resolver, opt.AllowedNet),
		},
		opt: opt,
	}
}

// Start the DTLS server.
func (s *DTLSListener) Start() error {
	Log.Info("starting listener", slog.Group("details", slog.String("id", s.id), slog.String("protocol", "dtls"), slog.String("addr", s.Addr)))

	if s.opt.NetNS.usesXSocket() {
		return errors.New("xsocket is not supported for DTLS listeners")
	}
	if s.opt.SocketOptions.active() {
		Log.Warn("socket options (fwmark, bind-interface) are not supported for DTLS listeners", "id", s.id)
	}

	host, port, err := net.SplitHostPort(s.Server.Addr)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: p}

	var listener net.Listener
	err = RunInNetNS(s.opt.NetNS, func() error {
		var e error
		listener, e = dtls.Listen("udp", addr, s.opt.DTLSConfig)
		return e
	})
	if err != nil {
		return err
	}
	s.Server.Listener = dtlsListener{listener}
	return s.Server.ActivateAndServe()
}

// Stop the server.
func (s *DTLSListener) Stop() error {
	Log.Info("stopping listener", slog.Group("details", slog.String("id", s.id), slog.String("protocol", "dtls"), slog.String("addr", s.Addr)))
	return s.Shutdown()
}

func (s *DTLSListener) String() string {
	return s.id
}

// dtlsListener wraps a dtls.Listener to return a dtlsConn that
// supports partial reads.
type dtlsListener struct {
	net.Listener
}

func (l dtlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	return &dtlsConn{Conn: conn}, err
}

// dtlsHandshakeTimeout bounds how long a DTLS handshake is given to complete.
//
// pion runs the handshake lazily, on the first Read or Write, and uses
// context.Background() for it, so the connection's read deadline does not
// apply: it is only consulted once the handshake is done. A peer that starts a
// handshake and then stops responding therefore pins the goroutine driving it
// forever. On a listener that is the connection goroutine dns.Server.Shutdown
// waits for, so the server never shuts down; on a resolver it is the pipeline's
// reader and writer, which leak for every abandoned connection.
// A variable rather than a constant so tests can shorten it; nothing else
// writes to it.
var dtlsHandshakeTimeout = 10 * time.Second

// dtlsConn wraps a dtls.Conn to support partial read operations. While
// github.com/pion/dtls/v3 returns a net.Conn, that Read() fails on
// slices that are smaller than the data available. This wrapper adds a
// buffer to allow github.com/miekg/dns to first read 2 bytes (size) and
// then the rest of the DNS packet.
//
// It also completes the handshake under a deadline before any data moves, see
// dtlsHandshakeTimeout.
type dtlsConn struct {
	net.Conn
	buf       *bytes.Buffer
	handshake sync.Once
	hsErr     error
}

// dtlsHandshaker is implemented by *dtls.Conn. Taken as an interface so the
// wrapper stays usable with any net.Conn, which the tests rely on.
type dtlsHandshaker interface {
	HandshakeContext(context.Context) error
}

// completeHandshake runs the DTLS handshake once, bounded by a deadline, and
// returns the same result to every later caller. Read and Write run on separate
// goroutines in the pipeline, so both have to go through here, and whichever
// arrives second waits for the first rather than starting its own.
func (c *dtlsConn) completeHandshake() error {
	c.handshake.Do(func() {
		hs, ok := c.Conn.(dtlsHandshaker)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dtlsHandshakeTimeout)
		defer cancel()
		c.hsErr = hs.HandshakeContext(ctx)
	})
	return c.hsErr
}

func (c *dtlsConn) Read(b []byte) (int, error) {
	if err := c.completeHandshake(); err != nil {
		return 0, err
	}
	var (
		n   int
		err error
	)
	if c.buf == nil || c.buf.Len() == 0 {
		tmp := make([]byte, 4096)
		n, err = c.Conn.Read(tmp)
		c.buf = bytes.NewBuffer(tmp[:n])
	}
	n, _ = c.buf.Read(b)
	return n, err
}

func (c *dtlsConn) Write(b []byte) (int, error) {
	if err := c.completeHandshake(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}
