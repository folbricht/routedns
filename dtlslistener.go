package rdns

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"time"

	"log/slog"

	"github.com/miekg/dns"
	"github.com/pion/dtls/v2"
)

// DTLSListener is a DNS listener/server for DNS-over-DTLS.
type DTLSListener struct {
	*dns.Server
	id string

	opt DTLSListenerOptions
}

var _ Listener = &DTLSListener{}

// DoTListenerOptions contains options used by the DNS-over-DTLS server.
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

	host, port, err := net.SplitHostPort(s.Server.Addr)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: p}

	s.opt.DTLSConfig.ConnectContextMaker = func() (context.Context, func()) {
		return context.WithTimeout(context.Background(), 2*time.Second)
	}

	listener, err := dtls.Listen("udp", addr, s.opt.DTLSConfig)
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

// dtlsConn wraps a dtls.Conn to support partial read operations. While
// github.com/pion/dtls/v2 returns a net.Conn, that Read() fails on
// slices that are smaller than the data available. This wrapper adds a
// buffer to allow github.com/miekg/dns to first read 2 bytes (size) and
// then the rest of the DNS packet.
type dtlsConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (c *dtlsConn) Read(b []byte) (int, error) {
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
