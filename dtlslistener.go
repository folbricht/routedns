package rdns

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/pion/dtls/v2"
	"github.com/sirupsen/logrus"
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
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "dtls", "addr": s.Addr}).Info("starting listener")

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
	s.Listener = listener
	return s.ActivateAndServe()
}

// Stop the server.
func (s *DTLSListener) Stop() error {
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "dtls", "addr": s.Addr}).Info("stopping listener")
	return s.Shutdown()
}

func (s *DTLSListener) String() string {
	return s.id
}
