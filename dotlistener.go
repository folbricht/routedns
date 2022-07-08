package rdns

import (
	"crypto/tls"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DoTListener is a DNS listener/server for DNS-over-TLS.
type DoTListener struct {
	*dns.Server
	id string
}

var _ Listener = &DoTListener{}

// DoTListenerOptions contains options used by the DNS-over-TLS server.
type DoTListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

// NewDoTListener returns an instance of a DNS-over-TLS listener.
func NewDoTListener(id, addr string, opt DoTListenerOptions, resolver Resolver) *DoTListener {
	return &DoTListener{
		id: id,
		Server: &dns.Server{
			Addr:      addr,
			Net:       "tcp-tls",
			TLSConfig: opt.TLSConfig,
			Handler:   listenHandler(id, "dot", addr, resolver, opt.AllowedNet),
		},
	}
}

// Start the Dot server.
func (s DoTListener) Start() error {
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "dot", "addr": s.Addr}).Info("starting listener")
	return s.ListenAndServe()
}

// Stop the server.
func (s DoTListener) Stop() error {
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "dot", "addr": s.Addr}).Info("stopping listener")
	return s.Shutdown()
}

func (s DoTListener) String() string {
	return s.id
}
