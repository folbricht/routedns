package rdns

import (
	"context"
	"crypto/tls"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Read/Write timeout in the admin server
const adminServerTimeout = 10 * time.Second

// AdminListener is a DNS listener/server for admin services.
type AdminListener struct {
	httpServer *http.Server
	quicServer *http3.Server

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
	s.httpServer = &http.Server{
		Addr:         s.addr,
		TLSConfig:    s.opt.TLSConfig,
		Handler:      s.mux,
		ReadTimeout:  adminServerTimeout,
		WriteTimeout: adminServerTimeout,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.httpServer.ServeTLS(ln, "", "")
}

// Start the admin server with QUIC transport.
func (s *AdminListener) startQUIC() error {
	s.quicServer = &http3.Server{
		Addr:       s.addr,
		TLSConfig:  s.opt.TLSConfig,
		Handler:    s.mux,
		QUICConfig: &quic.Config{},
	}
	return s.quicServer.ListenAndServe()
}

// Stop the server.
func (s *AdminListener) Stop() error {
	Log.Info("stopping listener",
		"id", s.id,
		"protocol", s.opt.Transport,
		"addr", s.addr)
	if s.opt.Transport == "quic" {
		return s.quicServer.Close()
	}
	return s.httpServer.Shutdown(context.Background())
}

func (s *AdminListener) String() string {
	return s.id
}
