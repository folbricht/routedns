package rdns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// QuicListener is a DNS listener/server for QUIC.
type QuicListener struct {
	addr string
	r    Resolver
	opt  QuicListenerOptions
	ln   quic.Listener
}

var _ Listener = &QuicListener{}

// QuicListenerOptions contains options used by the QUIC server.
type QuicListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

// NewQuicListener returns an instance of a QUIC listener.
func NewQuicListener(addr string, opt QuicListenerOptions, resolver Resolver) *QuicListener {
	if opt.TLSConfig == nil {
		opt.TLSConfig = new(tls.Config)
	}
	opt.TLSConfig.NextProtos = []string{"dq"}
	l := &QuicListener{
		addr: addr,
		r:    resolver,
		opt:  opt,
	}
	return l
}

// Start the QUIC server.
func (s QuicListener) Start() error {
	conf := quic.Config{}
	var err error
	s.ln, err = quic.ListenAddr(s.addr, s.opt.TLSConfig, &conf)
	if err != nil {
		return err
	}

	log := Log.WithFields(logrus.Fields{"protocol": "quic", "addr": s.addr})
	log.Info("starting listener")

	for {
		session, err := s.ln.Accept(context.Background())
		if err != nil {
			log.WithError(err).Warn("failed to accept")
			continue
		}

		log := log.WithField("client", session.RemoteAddr())
		go func() {
			handleClient(l, session, udpBackend)
		}()
	}
}

// Stop the server.
func (s QuicListener) Stop() error {
	Log.WithFields(logrus.Fields{"protocol": "quic", "addr": s.addr}).Info("stopping listener")
	return s.ln.Close()
}

func (s QuicListener) String() string {
	return fmt.Sprintf("QUIC(%s)", s.addr)
}

func (s QuicListener) dohHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.getHandler(w, r)
	case "POST":
		s.postHandler(w, r)
	default:
		http.Error(w, "only GET and POST allowed", http.StatusMethodNotAllowed)
	}
}

func (s QuicListener) getHandler(w http.ResponseWriter, r *http.Request) {
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

func (s QuicListener) postHandler(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.parseAndRespond(b, w, r)
}

func (s QuicListener) parseAndRespond(b []byte, w http.ResponseWriter, r *http.Request) {
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ci := ClientInfo{
		SourceIP: net.ParseIP(host),
	}
	log := Log.WithFields(logrus.Fields{"client": ci.SourceIP, "qname": qName(q), "protocol": "doh", "addr": s.Addr})
	log.Debug("received query")

	var err error
	a := new(dns.Msg)
	if isAllowed(s.opt.AllowedNet, ci.SourceIP) {
		log.WithField("resolver", s.r.String()).Trace("forwarding query to resolver")
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
