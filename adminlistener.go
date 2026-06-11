package rdns

import (
	"context"
	"crypto/tls"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Read/Write timeout in the admin server
const adminServerTimeout = 10 * time.Second

// AdminListener is a DNS listener/server for admin services.
type AdminListener struct {
	mu         sync.Mutex
	httpServer *http.Server
	quicServer *http3.Server
	// quicTransport/quicConn back quicServer. quic-go does not close a
	// caller-supplied PacketConn, so they are closed explicitly in Stop().
	quicTransport *quic.Transport
	quicConn      *net.UDPConn

	id   string
	addr string
	opt  AdminListenerOptions

	mux *http.ServeMux
}

var _ Listener = &AdminListener{}

// AdminListenerOptions contains options used by the admin service.
type AdminListenerOptions struct {
	ListenOptions

	// Transport protocol to run HTTPS over. "quic" or "tcp", defaults to "tcp".
	Transport string

	TLSConfig *tls.Config
}

// NewAdminListener returns an instance of an admin service listener.
func NewAdminListener(id, addr string, opt AdminListenerOptions) (*AdminListener, error) {
	switch opt.Transport {
	case "tcp", "":
		opt.Transport = "tcp"
	case "quic":
		opt.Transport = "quic"
	default:
		return nil, fmt.Errorf("unknown protocol: '%s'", opt.Transport)
	}

	l := &AdminListener{
		id:   id,
		addr: addr,
		opt:  opt,
		mux:  http.NewServeMux(),
	}
	// Serve metrics.
	l.mux.Handle("/routedns/vars", expvar.Handler())
	return l, nil
}

// Start the admin server.
func (s *AdminListener) Start() error {
	Log.Info("starting listener",
		"id", s.id,
		"protocol", s.opt.Transport,
		"addr", s.addr)
	if s.opt.Transport == "quic" {
		return s.startQUIC()
	}
	return s.startTCP()
}

// Start the admin server with TCP transport.
func (s *AdminListener) startTCP() error {
	httpServer := &http.Server{
		Addr:         s.addr,
		TLSConfig:    s.opt.TLSConfig,
		Handler:      s.mux,
		ReadTimeout:  adminServerTimeout,
		WriteTimeout: adminServerTimeout,
	}
	s.mu.Lock()
	s.httpServer = httpServer
	s.mu.Unlock()

	ln, err := ListenInNetNS(context.Background(), s.opt.NetNS, "tcp", s.addr, s.opt.SocketOptions)
	if err != nil {
		return err
	}
	ln = proxyProtocolListener(ln, s.opt.ProxyProtocol)
	defer ln.Close()
	return httpServer.ServeTLS(ln, "", "")
}

// Start the admin server with QUIC transport.
func (s *AdminListener) startQUIC() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	udpConn, err := ListenUDPInNetNS(context.Background(), s.opt.NetNS, "udp", udpAddr, s.opt.SocketOptions)
	if err != nil {
		return err
	}
	transport := &quic.Transport{Conn: udpConn}
	tlsConf := http3.ConfigureTLSConfig(s.opt.TLSConfig)
	quicLn, err := transport.ListenEarly(tlsConf, &quic.Config{})
	if err != nil {
		udpConn.Close()
		return err
	}
	quicServer := &http3.Server{
		TLSConfig:  s.opt.TLSConfig,
		Handler:    s.mux,
		QUICConfig: &quic.Config{},
	}
	s.mu.Lock()
	s.quicServer = quicServer
	s.quicTransport = transport
	s.quicConn = udpConn
	s.mu.Unlock()
	return quicServer.ServeListener(quicLn)
}

// Stop the server.
func (s *AdminListener) Stop() error {
	Log.Info("stopping listener",
		"id", s.id,
		"protocol", s.opt.Transport,
		"addr", s.addr)
	s.mu.Lock()
	httpServer, quicServer := s.httpServer, s.quicServer
	quicTransport, quicConn := s.quicTransport, s.quicConn
	s.mu.Unlock()
	if s.opt.Transport == "quic" {
		if quicServer == nil {
			return nil
		}
		err := quicServer.Close()
		// quic-go's Transport.Close does not close a caller-supplied
		// PacketConn, so close both explicitly to avoid leaking the socket
		// on each rebuild.
		quicTransport.Close()
		quicConn.Close()
		return err
	}
	if httpServer == nil {
		return nil
	}
	return httpServer.Shutdown(context.Background())
}

func (s *AdminListener) String() string {
	return s.id
}
