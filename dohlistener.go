package rdns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

// DoHListener is a DNS listener/server for DNS-over-HTTPS.
type DoHListener struct {
	*http.Server
	r Resolver
}

var _ Listener = &DoHListener{}

// DoTListenerOptions contains options used by the DNS-over-HTTPS server.
type DoHListenerOptions struct {
	TLSConfig *tls.Config
}

// NewDoTListener returns an instance of either a UDP or TCP DNS listener.
func NewDoHListener(addr string, opt DoHListenerOptions, resolver Resolver) *DoHListener {
	l := &DoHListener{
		Server: &http.Server{
			Addr:      addr,
			TLSConfig: opt.TLSConfig,
		},
		r: resolver,
	}
	mux := http.NewServeMux()
	mux.Handle("/dns-query", http.HandlerFunc(l.dohHandler))
	l.Handler = mux
	return l
}

// Start the DoH server.
func (s DoHListener) Start() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.ServeTLS(ln, "", "")
}

// Stop the server.
func (s DoHListener) Stop() error {
	return s.Shutdown(context.Background())
}

func (s DoHListener) String() string {
	return fmt.Sprintf("DoH(%s)", s.Addr)
}

func (s DoHListener) dohHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.getHandler(w, r)
	case "POST":
		s.postHandler(w, r)
	default:
		http.Error(w, "only GET and POST allowed", http.StatusMethodNotAllowed)
	}
}

func (s DoHListener) getHandler(w http.ResponseWriter, r *http.Request) {
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

func (s DoHListener) postHandler(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.parseAndRespond(b, w, r)
}

func (s DoHListener) parseAndRespond(b []byte, w http.ResponseWriter, r *http.Request) {
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	Log.Printf("received query for '%s' forwarded to %s", qName(q), s.r.String())
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ci := ClientInfo{
		SourceIP: net.ParseIP(host),
	}
	a, err := s.r.Resolve(q, ci)
	if err != nil {
		Log.Printf("failed to resolve '%s' : %s", qName(q), err)
		a = new(dns.Msg)
		a.SetRcode(q, dns.RcodeServerFailure)
	}
	out, err := a.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/dns-message")
	w.Write(out)
}
