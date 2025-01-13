package rdns

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"

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
		Log.Error("Failed to generate HPKE key pair", "error", err)
		return nil, err
	}

	dohOpt := DoHListenerOptions{
		TLSConfig: opt.TLSConfig,
		isChild:   true,
	}
	dohListen, err := NewDoHListener(id, addr, dohOpt, resolver)
	if err != nil {
		Log.Error("Failed to spawn DoH listener", "error", err)
		return nil, err
	}

	l := &ODoHListener{
		id:          id,
		addr:        addr,
		r:           resolver,
		opt:         opt,
		proxyClient: &http.Client{},
		odohKeyPair: keyPair,
		doh:         dohListen,
	}

	switch opt.OdohMode {
	case "proxy":
		http.HandleFunc(ODOH_PROXY_PATH, l.ODoHproxyHandler)
	case "target":
		http.HandleFunc(ODOH_QUERY_PATH, l.ODoHqueryHandler)
		http.HandleFunc(ODOH_CONFIG_PATH, l.configHandler)
	default:
		http.HandleFunc(ODOH_PROXY_PATH, l.ODoHproxyHandler)
		http.HandleFunc(ODOH_QUERY_PATH, l.ODoHqueryHandler)
		http.HandleFunc(ODOH_CONFIG_PATH, l.configHandler)
	}
	return l, nil
}

func (s *ODoHListener) Start() error {
	return s.doh.Start()
}

func (s *ODoHListener) Stop() error {
	return s.doh.Stop()
}

func (s *ODoHListener) ODoHproxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	contentType := r.Header.Get("Content-Type")
	host := r.URL.Query().Get("targethost")
	if host == "" {
		http.Error(w, "no targethost specified", http.StatusBadRequest)
		return
	}
	path := r.URL.Query().Get("targetpath")
	if path == "" {
		http.Error(w, "no targetpath specified", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	if response.StatusCode != 200 {
		http.Error(w, http.StatusText(response.StatusCode), response.StatusCode)
		return
	}

	defer response.Body.Close()
	rb, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(rb)
}

func forwardProxyRequest(client *http.Client, targethost string, targetPath string, body []byte, contentType string) (*http.Response, error) {
	targetURL := "https://" + targethost + targetPath
	req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
	if err != nil {
		Log.Error("Failed creating target POST request", "error", err)
		return nil, errors.New("failed creating target POST request")
	}
	req.Header.Set("Content-Type", contentType)
	return client.Do(req)
}

func (s *ODoHListener) ODoHqueryHandler(w http.ResponseWriter, r *http.Request) {
	qHeader := r.Header.Get("Content-Type")
	if r.Method != "POST" || qHeader == DOH_CONTENT_TYPE {
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
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
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
		http.Error(w, "failed to create oblivious response", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", ODOH_CONTENT_TYPE)
	w.Write(obliviousResponse.Marshal())
}

func (s *ODoHListener) String() string {
	return s.id
}

func (s *ODoHListener) configHandler(w http.ResponseWriter, r *http.Request) {
	configSet := []odoh.ObliviousDoHConfig{s.odohKeyPair.Config}
	configs := odoh.CreateObliviousDoHConfigs(configSet)
	w.Write(configs.Marshal())
}

func getKeyPair(opt ODoHListenerOptions) (odoh.ObliviousDoHKeyPair, error) {
	var seed []byte
	var err error
	if opt.KeySeed != "" {
		seed, err = hex.DecodeString(opt.KeySeed)
		if err != nil {
			Log.Error("Failed to read key seed", "error", err)
		}
	} else {
		seed = make([]byte, defaultSeedLength)
		if _, err := rand.Read(seed); err != nil {
			Log.Error("Failed to generate random seed", "error", err)
		}
	}
	return odoh.CreateKeyPairFromSeed(kemID, kdfID, aeadID, seed)
}
