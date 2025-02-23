package rdns

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cisco/go-hpke"
	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const (
	// HPKE constants
	kemID  = hpke.DHKEM_X25519
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AESGCM128

	defaultSeedLength = 32
)

// ODoHListener is an Oblivious DNS over HTTPS listener.
type ODoHListener struct {
	id          string
	addr        string
	proxyClient *http.Client // Client for proxy forwarding if acting as ODoH proxy
	doh         *DoHListener
	config      []byte

	r           Resolver // Forwarding DNS queries if acting as ODoH Target
	opt         ODoHListenerOptions
	odohKeyPair odoh.ObliviousDoHKeyPair
}

type ODoHListenerOptions struct {
	ListenOptions

	OdohMode  string
	AllowDoH  bool
	KeySeed   string
	TLSConfig *tls.Config
}

var _ Listener = &ODoHListener{}

// NewODoHListener returns an instance of an oblivious DNS-over-HTTPS listener.
func NewODoHListener(id, addr string, opt ODoHListenerOptions, resolver Resolver) (*ODoHListener, error) {
	keyPair, err := getKeyPair(opt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate HPKE key pair: %w", err)
	}

	configSet := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{keyPair.Config})
	l := &ODoHListener{
		id:          id,
		addr:        addr,
		r:           resolver,
		opt:         opt,
		proxyClient: &http.Client{},
		odohKeyPair: keyPair,
		config:      configSet.Marshal(),
	}

	mux := http.NewServeMux()
	switch opt.OdohMode {
	case "dual":
		mux.HandleFunc(ODOH_PROXY_PATH, l.ODoHproxyHandler)
		mux.HandleFunc(ODOH_QUERY_PATH, l.ODoHqueryHandler)
		mux.HandleFunc(ODOH_CONFIG_PATH, l.configHandler)
	case "proxy":
		mux.HandleFunc(ODOH_PROXY_PATH, l.ODoHproxyHandler)
	case "target", "":
		mux.HandleFunc(ODOH_QUERY_PATH, l.ODoHqueryHandler)
		mux.HandleFunc(ODOH_CONFIG_PATH, l.configHandler)
	}

	dohOpt := DoHListenerOptions{
		TLSConfig: opt.TLSConfig,
		customMux: mux,
	}
	dohListen, err := NewDoHListener(id, addr, dohOpt, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to spawn DoH listener:  %w", err)
	}

	l.doh = dohListen
	return l, nil
}

func (s *ODoHListener) Start() error {
	return s.doh.Start()
}

func (s *ODoHListener) Stop() error {
	return s.doh.Stop()
}

func (s *ODoHListener) ODoHproxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType == "" || contentType != ODOH_CONTENT_TYPE {
		http.Error(w, "invalid or missing Content-Type", http.StatusBadRequest)
		return
	}

	host := r.URL.Query().Get("targethost")
	if host == "" {
		http.Error(w, "no targethost specified", http.StatusBadRequest)
		return
	}

	if len(host) > 253 || !regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`).MatchString(host) {
		http.Error(w, "invalid targethost", http.StatusBadRequest)
		return
	}

	path := r.URL.Query().Get("targetpath")
	if path == "" || len(path) > 1024 || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		http.Error(w, "invalid targetpath", http.StatusBadRequest)
		return
	}

	b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	Log.Debug("forwarding query to ODoH target",
		slog.String("client", r.RemoteAddr),
		slog.String("target", host),
	)
	response, err := forwardProxyRequest(s.proxyClient, host, path, b, contentType)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		http.Error(w, http.StatusText(response.StatusCode), response.StatusCode)
		return
	}

	w.Header().Set("Content-Type", ODOH_CONTENT_TYPE)
	if _, err := io.Copy(w, response.Body); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func forwardProxyRequest(client *http.Client, host string, path string, body []byte, contentType string) (*http.Response, error) {
	url := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   path,
	}
	targetURL := url.String()
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		Log.Error("Failed creating target POST request", "error", err)
		return nil, errors.New("failed creating target POST request")
	}
	req.Header.Set("Content-Type", contentType)
	return client.Do(req)
}

func (s *ODoHListener) ODoHqueryHandler(w http.ResponseWriter, r *http.Request) {
	qHeader := r.Header.Get("Content-Type")
	if r.Method != http.MethodPost || qHeader == DOH_CONTENT_TYPE {
		if s.opt.AllowDoH {
			Log.Debug("Forwarding DoH query")
			s.doh.dohHandler(w, r)
			return
		} else {
			Log.Debug("DoH queries disabled, dropping DoH message")
			http.Error(w, "only contentType oblivious-dns-message allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if qHeader != ODOH_CONTENT_TYPE {
		http.Error(w, "only contentType oblivious-dns-message allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	msg, err := odoh.UnmarshalDNSMessage(b)
	if err != nil {
		http.Error(w, "error while parsing oblivious query", http.StatusBadRequest)
		return
	}

	obliviousQuery, responseContext, err := s.odohKeyPair.DecryptQuery(msg)
	if err != nil {
		http.Error(w, "error while decrypting oblivious query", http.StatusBadRequest)
		return
	}

	q := &dns.Msg{}
	if q.Unpack(obliviousQuery.Message()) != nil {
		http.Error(w, "unpacking oblivious query failed", http.StatusBadRequest)
		return
	}

	a, err := s.r.Resolve(q, ClientInfo{Listener: s.id, TLSServerName: r.TLS.ServerName})
	if err != nil {
		Log.Error("failed to resolve", "error", err)
		a = new(dns.Msg)
		a.SetRcode(q, dns.RcodeServerFailure)
	}

	p, err := a.Pack()
	if err != nil {
		Log.Error("failed to encode response", "error", err)
		return
	}

	response := odoh.CreateObliviousDNSResponse(p, 0)
	obliviousResponse, err := responseContext.EncryptResponse(response)
	if err != nil {
		http.Error(w, "failed to encrypt oblivious response", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", ODOH_CONTENT_TYPE)
	w.Write(obliviousResponse.Marshal())
}

func (s *ODoHListener) String() string {
	return s.id
}

func (s *ODoHListener) configHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(s.config)
}

func getKeyPair(opt ODoHListenerOptions) (odoh.ObliviousDoHKeyPair, error) {
	var seed []byte
	var err error
	if opt.KeySeed != "" {
		seed, err = hex.DecodeString(opt.KeySeed)
		if err != nil {
			return odoh.ObliviousDoHKeyPair{}, fmt.Errorf("failed to read key seed: %w", err)
		}
	} else {
		seed = make([]byte, defaultSeedLength)
		if _, err := rand.Read(seed); err != nil {
			return odoh.ObliviousDoHKeyPair{}, fmt.Errorf("failed to generate random seed: %w", err)
		}
	}
	return odoh.CreateKeyPairFromSeed(kemID, kdfID, aeadID, seed)
}
