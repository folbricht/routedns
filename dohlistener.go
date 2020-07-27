package rdns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Read/Write timeout in the DoH server
const dohServerTimeout = 10 * time.Second

// DoHListener is a DNS listener/server for DNS-over-HTTPS.
type DoHListener struct {
	httpServer *http.Server
	quicServer *http3.Server

	id   string
	addr string
	r    Resolver
	opt  DoHListenerOptions

	mux *http.ServeMux
}

var _ Listener = &DoHListener{}

// DoHListenerOptions contains options used by the DNS-over-HTTPS server.
type DoHListenerOptions struct {
	ListenOptions

	// Transport protocol to run HTTPS over. "quic" or "tcp", defaults to "tcp".
	Transport string

	TLSConfig *tls.Config

	// IP(v4/v6) of a known reverse proxy in front of this server.
	HTTPProxyAddr net.IP
}

// NewDoHListener returns an instance of a DNS-over-HTTPS listener.
func NewDoHListener(id, addr string, opt DoHListenerOptions, resolver Resolver) (*DoHListener, error) {
	switch opt.Transport {
	case "tcp", "":
		opt.Transport = "tcp"
	case "quic":
		opt.Transport = "quic"
	default:
		return nil, fmt.Errorf("unknown protocol: '%s'", opt.Transport)
	}

	l := &DoHListener{
		id:   id,
		addr: addr,
		r:    resolver,
		opt:  opt,
		mux:  http.NewServeMux(),
	}
	l.mux.Handle("/dns-query", http.HandlerFunc(l.dohHandler))
	return l, nil
}

// Start the DoH server.
func (s *DoHListener) Start() error {
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "doh", "addr": s.addr}).Info("starting listener")
	if s.opt.Transport == "quic" {
		return s.startQUIC()
	}
	return s.startTCP()
}

// Start the DoH server with TCP transport.
func (s *DoHListener) startTCP() error {
	s.httpServer = &http.Server{
		Addr:         s.addr,
		TLSConfig:    s.opt.TLSConfig,
		Handler:      s.mux,
		ReadTimeout:  dohServerTimeout,
		WriteTimeout: dohServerTimeout,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.httpServer.ServeTLS(ln, "", "")
}

// Start the DoH server with QUIC transport.
func (s *DoHListener) startQUIC() error {
	s.quicServer = &http3.Server{
		Server: &http.Server{
			Addr:         s.addr,
			TLSConfig:    s.opt.TLSConfig,
			Handler:      s.mux,
			ReadTimeout:  dohServerTimeout,
			WriteTimeout: dohServerTimeout,
		},
		QuicConfig: &quic.Config{},
	}
	return s.quicServer.ListenAndServe()
}

// Stop the server.
func (s *DoHListener) Stop() error {
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "doh", "addr": s.addr}).Info("stopping listener")
	if s.opt.Transport == "quic" {
		return s.quicServer.Close()
	}
	return s.httpServer.Shutdown(context.Background())
}

func (s *DoHListener) String() string {
	return s.id
}

func (s *DoHListener) dohHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.getHandler(w, r)
	case "POST":
		s.postHandler(w, r)
	default:
		http.Error(w, "only GET and POST allowed", http.StatusMethodNotAllowed)
	}
}

func (s *DoHListener) getHandler(w http.ResponseWriter, r *http.Request) {
	b64, ok := r.URL.Query()["dns"]
	if !ok {
		http.Error(w, "no dns query parameter found", http.StatusBadRequest)
		return
	}
	if len(b64) < 1 {
		http.Error(w, "no dns query value found", http.StatusBadRequest)
		return
	}
	b, err := base64.RawURLEncoding.DecodeString(b64[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.parseAndRespond(b, w, r)
}

func (s *DoHListener) postHandler(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.parseAndRespond(b, w, r)
}

// Extract the client address from the HTTP headers, accounting for known
// reverse proxies.
func (s *DoHListener) extractClientAddress(r *http.Request) net.IP {
	client, _, _ := net.SplitHostPort(r.RemoteAddr)
	clientIP := net.ParseIP(client)

	// TODO: Prefer RFC 7239 Forwarded once https://github.com/golang/go/issues/30963
	//       is resolved and provides a safe parser.
	xForwardedFor := r.Header.Get("X-Forwarded-For")

	// Simple case: No proxy (or empty/long X-Forwarded-For).
	if s.opt.HTTPProxyAddr == nil || xForwardedFor == "" || len(xForwardedFor) >= 1024 {
		return clientIP
	}

	// If our client is a reverse proxy then use the last entry in X-Forwarded-For.
	chain := strings.Split(xForwardedFor, ", ")
	if clientIP != nil && s.opt.HTTPProxyAddr.Equal(clientIP) {
		if ip := net.ParseIP(chain[len(chain)-1]); ip != nil {
			// Ignore XFF whe the client is local to the proxy.
			if !ip.IsLoopback() {
				return ip
			}
		}
	}

	// TODO: Decide whether to go deeper into the XFF chain (eg. two reverse proxies).
	//       We have to be careful if we do, because then we're trusting an XFF that
	//       may have been provided externally.

	return clientIP
}

func (s *DoHListener) parseAndRespond(b []byte, w http.ResponseWriter, r *http.Request) {
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Extract the remote host address from the HTTP headers.
	clientIP := s.extractClientAddress(r)
	if clientIP == nil {
		http.Error(w, "Invalid RemoteAddr", http.StatusBadRequest)
		return
	}
	ci := ClientInfo{
		SourceIP: clientIP,
	}
	log := Log.WithFields(logrus.Fields{"id": s.id, "client": ci.SourceIP, "qname": qName(q), "protocol": "doh", "addr": s.addr})
	log.Debug("received query")

	var err error
	a := new(dns.Msg)
	if isAllowed(s.opt.AllowedNet, ci.SourceIP) {
		log.WithField("resolver", s.r.String()).Debug("forwarding query to resolver")
		a, err = s.r.Resolve(q, ci)
		if err != nil {
			log.WithError(err).Error("failed to resolve")
			a = new(dns.Msg)
			a.SetRcode(q, dns.RcodeServerFailure)
		}
	} else {
		log.Debug("refusing client ip")
		a.SetRcode(q, dns.RcodeRefused)
	}

	// A nil response from the resolvers means "drop", return blank response
	if a == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Pad the packet according to rfc8467 and rfc7830
	padAnswer(q, a)

	out, err := a.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/dns-message")
	_, _ = w.Write(out)
}
