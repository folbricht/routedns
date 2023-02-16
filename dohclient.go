package rdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/jtacoma/uritemplates"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

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
	// Parse the URL template
	template, err := uritemplates.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	var tr http.RoundTripper
	switch opt.Transport {
	case "tcp", "":
		tr, err = dohTcpTransport(opt)
	case "quic":
		tr, err = dohQuicTransport(endpoint, opt)
	default:
		err = fmt.Errorf("unknown protocol: '%s'", opt.Transport)
	}
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: tr,
	}

	if opt.Method == "" {
		opt.Method = "POST"
	}
	if opt.Method != "POST" && opt.Method != "GET" {
		return nil, fmt.Errorf("unsupported method '%s'", opt.Method)
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
	logger(d.id, q, ci).WithFields(logrus.Fields{
		"resolver": d.endpoint,
		"protocol": "doh",
		"method":   d.opt.Method,
	}).Debug("querying upstream resolver")

	// Add padding before sending the query over HTTPS
	padQuery(q)

	d.metrics.query.Add(1)
	switch d.opt.Method {
	case "POST":
		return d.ResolvePOST(q)
	case "GET":
		return d.ResolveGET(q)
	}
	return nil, errors.New("unsupported method")
}

// ResolvePOST resolves a DNS query via DNS-over-HTTP using the POST method.
func (d *DoHClient) ResolvePOST(q *dns.Msg) (*dns.Msg, error) {
	// Pack the DNS query into wire format
	b, err := q.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}
	// The URL could be a template. Process it without values since POST doesn't use variables in the URL.
	u, err := d.template.Expand(map[string]interface{}{})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}
	req, err := http.NewRequest("POST", u, bytes.NewReader(b))
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		d.metrics.err.Add("post", 1)
		return nil, err
	}
	defer resp.Body.Close()
	return d.responseFromHTTP(resp)
}

// ResolveGET resolves a DNS query via DNS-over-HTTP using the GET method.
func (d *DoHClient) ResolveGET(q *dns.Msg) (*dns.Msg, error) {
	// Pack the DNS query into wire format
	b, err := q.Pack()
	if err != nil {
		d.metrics.err.Add("pack", 1)
		return nil, err
	}
	// Encode the query as base64url without padding
	b64 := base64.RawURLEncoding.EncodeToString(b)

	// The URL must be a template. Process it with the "dns" param containing the encoded query.
	u, err := d.template.Expand(map[string]interface{}{"dns": b64})
	if err != nil {
		d.metrics.err.Add("template", 1)
		return nil, err
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		d.metrics.err.Add("http", 1)
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		d.metrics.err.Add("get", 1)
		return nil, err
	}
	defer resp.Body.Close()
	return d.responseFromHTTP(resp)
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
	rb, err := ioutil.ReadAll(resp.Body)
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
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       opt.TLSConfig,
		DisableCompression:    true,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	// If we're using a custom tls.Config, HTTP2 isn't enabled by default in
	// the HTTP library. Turn it on for this transport.
	if tr.TLSClientConfig != nil {
		if err := http2.ConfigureTransport(tr); err != nil {
			return nil, err
		}
	}

	// Use a custom dialer if a bootstrap address or local address was provided
	if opt.BootstrapAddr != "" || opt.LocalAddr != nil {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: opt.LocalAddr}}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if opt.BootstrapAddr != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(opt.BootstrapAddr, port)
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
	tlsConfig.ServerName = u.Hostname()
	lAddr := net.IPv4zero
	if opt.LocalAddr != nil {
		lAddr = opt.LocalAddr
	}

	// When using a custom dialer, we have to track/close connections ourselves
	pool := new(udpConnPool)
	dialer := func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
		return quicDial(u.Hostname(), addr, lAddr, tlsConfig, config, pool)
	}
	if opt.BootstrapAddr != "" {
		dialer = func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addr = net.JoinHostPort(opt.BootstrapAddr, port)
			return quicDial(u.Hostname(), addr, lAddr, tlsConfig, config, pool)
		}
	}

	tr := &http3.RoundTripper{
		TLSClientConfig: tlsConfig,
		QuicConfig: &quic.Config{
			TokenStore: quic.NewLRUTokenStore(10, 10),
		},
		Dial: dialer,
	}
	return &http3ReliableRoundTripper{tr, pool}, nil
}

func quicDial(hostname, rAddr string, lAddr net.IP, tlsConfig *tls.Config, config *quic.Config, pool *udpConnPool) (quic.EarlyConnection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", rAddr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr, Port: 0})
	if err != nil {
		return nil, err
	}
	pool.add(udpConn)
	return quic.DialEarly(udpConn, udpAddr, hostname, tlsConfig, config)
}

// Wrapper for http3.RoundTripper due to https://github.com/quic-go/quic-go/issues/765
// This wrapper will transparently re-open expired connections. Should be removed once the issue
// has been fixed upstream.
type http3ReliableRoundTripper struct {
	*http3.RoundTripper
	pool *udpConnPool
}

func (r *http3ReliableRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.RoundTripper.RoundTrip(req)
	if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
		r.pool.closeAll()
		r.RoundTripper.Close()
		resp, err = r.RoundTripper.RoundTrip(req)
	}
	return resp, err
}

// UDP connection pool. Also a workaround for for the http3.RoundTripper. When using a custom
// dialer that open its own UDP connections, http3.RoundTripper doesn't close them when the
// remote terminates a connection, or when calling Close(). So we have to keep track of the
// connections and close them all before calling Close() on the http3.RoundTripper.
type udpConnPool struct {
	conns []*net.UDPConn
	mu    sync.Mutex
}

func (p *udpConnPool) add(conn *net.UDPConn) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = append(p.conns, conn)
}

func (p *udpConnPool) closeAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = nil
}
