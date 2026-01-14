package rdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"log/slog"

	"github.com/jtacoma/uritemplates"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// defaultDoHIdleTimeout is the default idle connection timeout for DoH TCP transport.
const defaultDoHIdleTimeout = 30 * time.Second

// DoHClientOptions contains options used by the DNS-over-HTTP resolver.
type DoHClientOptions struct {
	// Query method, either GET or POST. If empty, POST is used.
	Method string

	// Bootstrap address - IP to use for the service instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Transport protocol to run HTTPS over. "quic" or "tcp", defaults to "tcp".
	Transport string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	TLSConfig *tls.Config

	QueryTimeout time.Duration

	// IdleTimeout is the maximum amount of time an idle connection will remain
	// open before being closed. For TCP transport, defaults to 30 seconds if not set.
	// For QUIC transport, defaults to the quic-go library default if not set. Note
	// that for QUIC, the actual timeout is the minimum of client and server values.
	IdleTimeout time.Duration

	// Optional dialer, e.g. proxy
	Dialer Dialer

	Use0RTT bool
}

// DoHClient is a DNS-over-HTTP resolver with support fot HTTP/2.
type DoHClient struct {
	id       string
	endpoint string
	template *uritemplates.UriTemplate
	client   *http.Client
	opt      DoHClientOptions
	metrics  *ListenerMetrics
}

var _ Resolver = &DoHClient{}

func NewDoHClient(id, endpoint string, opt DoHClientOptions) (*DoHClient, error) {
	// Validate options
	if opt.IdleTimeout < 0 {
		return nil, fmt.Errorf("idle-timeout must not be negative")
	}

	// Parse the URL template
	template, err := uritemplates.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	// Configure the HTTP Client and Transport based on connection options
	var client *http.Client
	switch opt.Transport {
	case "tcp", "":
		tr, err := dohTcpTransport(opt)
		if err != nil {
			return nil, err
		}
		client = &http.Client{Transport: tr}
	case "quic":
		tr, err := dohQuicTransport(endpoint, opt)
		if err != nil {
			return nil, err
		}
		client = &http.Client{Transport: tr}
	default:
		return nil, fmt.Errorf("unknown protocol: '%s'", opt.Transport)
	}

	if opt.Method == "" {
		opt.Method = "POST"
	}
	if opt.Method != "POST" && opt.Method != "GET" {
		return nil, fmt.Errorf("unsupported method '%s'", opt.Method)
	}
	if opt.QueryTimeout == 0 {
		opt.QueryTimeout = defaultQueryTimeout
	}

	return &DoHClient{
		id:       id,
		endpoint: endpoint,
		template: template,
		client:   client,
		opt:      opt,
		metrics:  NewListenerMetrics("client", id),
	}, nil
}

// Resolve a DNS query.
func (d *DoHClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	// Packing a message is not always a read-only operation, make a copy
	q = q.Copy()
	log := logger(d.id, q, ci)

	log.Debug("querying upstream resolver",
		slog.String("resolver", d.endpoint),
		slog.String("protocol", "doh"),
		slog.String("method", d.opt.Method),
	)

	// Add padding before sending the query over HTTPS
	padQuery(q)

	// Pack the DNS query into wire format
	msg, err := q.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}

	d.metrics.query.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), d.opt.QueryTimeout)
	defer cancel()

	// Build a DoH request and execute it
	req, err := d.buildRequest(ctx, msg)
	if err != nil {
		return nil, err
	}
	resp, err := d.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Extract the DNS response from the HTTP response
	return d.responseFromHTTP(resp)
}

func (d *DoHClient) buildRequest(ctx context.Context, msg []byte) (*http.Request, error) {
	switch d.opt.Method {
	case "POST":
		return d.buildPostRequest(ctx, msg)
	case "GET":
		return d.buildGetRequest(ctx, msg)
	default:
		return nil, errors.New("unsupported method")
	}
}

func (d *DoHClient) do(req *http.Request) (*http.Response, error) {
	resp, err := d.client.Do(req)
	if err != nil {
		d.metrics.err.Add(req.Method, 1)
		return nil, err
	}
	return resp, err
}

func (d *DoHClient) buildPostRequest(ctx context.Context, msg []byte) (*http.Request, error) {
	// The URL could be a template. Process it without values since POST doesn't use variables in the URL.
	u, err := d.template.Expand(map[string]interface{}{})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(msg))
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")
	return req, nil
}

func (d *DoHClient) buildGetRequest(ctx context.Context, msg []byte) (*http.Request, error) {
	// Encode the query as base64url
	b64 := base64.RawURLEncoding.EncodeToString(msg)

	// The URL must be a template. Process it with the "dns" param containing the encoded query.
	u, err := d.template.Expand(map[string]interface{}{"dns": b64})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}

	method := http.MethodGet
	if d.opt.Use0RTT && d.opt.Transport == "quic" {
		method = http3.MethodGet0RTT
	}

	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	return req, nil
}

func (d *DoHClient) String() string {
	return d.id
}

// Check the HTTP response status code and parse out the response DNS message.
func (d *DoHClient) responseFromHTTP(resp *http.Response) (*dns.Msg, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		d.metrics.err.Add(fmt.Sprintf("http%d", resp.StatusCode), 1)
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		d.metrics.err.Add("read", 1)
		return nil, err
	}
	a := new(dns.Msg)
	err = a.Unpack(rb)
	if err != nil {
		d.metrics.err.Add("unpack", 1)
	} else {
		d.metrics.response.Add(rCode(a), 1)
	}
	return a, err
}

func dohTcpTransport(opt DoHClientOptions) (http.RoundTripper, error) {
	idleTimeout := opt.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultDoHIdleTimeout
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       opt.TLSConfig,
		DisableCompression:    true,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       idleTimeout,
	}
	// If we're using a custom tls.Config, HTTP2 isn't enabled by default in
	// the HTTP library. Turn it on for this transport.
	if tr.TLSClientConfig != nil {
		if err := http2.ConfigureTransport(tr); err != nil {
			return nil, err
		}
	}

	// Use a custom dialer if a bootstrap address or local address was provided
	if opt.BootstrapAddr != "" || opt.LocalAddr != nil || opt.Dialer != nil {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: opt.LocalAddr}}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if opt.BootstrapAddr != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(opt.BootstrapAddr, port)
			}
			if opt.Dialer != nil {
				return opt.Dialer.Dial(network, addr)
			}
			return d.DialContext(ctx, network, addr)
		}
	}
	return tr, nil
}

func dohQuicTransport(endpoint string, opt DoHClientOptions) (http.RoundTripper, error) {
	var tlsConfig *tls.Config
	if opt.TLSConfig == nil {
		tlsConfig = new(tls.Config)
	} else {
		tlsConfig = opt.TLSConfig.Clone()
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	// enable TLS session caching for session resumption and 0-RTT
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(100)
	tlsConfig.ServerName = u.Hostname()
	lAddr := net.IPv4zero
	if opt.LocalAddr != nil {
		lAddr = opt.LocalAddr
	}

	// Initialize the local UDP connection, it'll be re-used for all connections
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr, Port: 0})
	if err != nil {
		Log.Error("couldn't listen on UDP socket on local address", "error", err, "local", lAddr.String())
		return nil, err
	}
	quicTransport := &quic.Transport{Conn: udpConn}

	dialFunc := quicTransport.Dial
	if opt.Use0RTT {
		dialFunc = quicTransport.DialEarly
	}

	dialer := func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
		if opt.BootstrapAddr != "" {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addr = net.JoinHostPort(opt.BootstrapAddr, port)
		}
		rAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		return dialFunc(ctx, rAddr, tlsConfig, config)
	}

	quicConfig := &quic.Config{
		TokenStore: quic.NewLRUTokenStore(10, 10),
	}
	if opt.IdleTimeout > 0 {
		quicConfig.MaxIdleTimeout = opt.IdleTimeout
	}

	tr := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial:            dialer,
	}
	return tr, nil
}
