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

	QueryTimeout time.Duration

	// Optional dialer, e.g. proxy
	Dialer Dialer

	Use0RTT bool
}

// Returns an HTTP client based on the DoH options
func (opt DoHClientOptions) client(endpoint string) (*http.Client, error) {
	var (
		tr  http.RoundTripper
		err error
	)
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
	return &http.Client{
		Transport: tr,
	}, nil
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

	client, err := opt.client(endpoint)
	if err != nil {
		return nil, err
	}

	if opt.Method == "" {
		opt.Method = "POST"
	}
	if opt.Use0RTT && opt.Transport == "quic" {
		opt.Method = "GET"
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

	logger(d.id, q, ci).WithFields(logrus.Fields{
		"resolver": d.endpoint,
		"protocol": "doh",
		"method":   d.opt.Method,
	}).Debug("querying upstream resolver")

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

	dialer := func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
		return newQuicConnection(u.Hostname(), addr, lAddr, tlsConfig, config)
	}
	if opt.BootstrapAddr != "" {
		dialer = func(ctx context.Context, addr string, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addr = net.JoinHostPort(opt.BootstrapAddr, port)
			return newQuicConnection(u.Hostname(), addr, lAddr, tlsConfig, config)
		}
	}

	tr := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			TokenStore: quic.NewLRUTokenStore(10, 10),
		},
		Dial: dialer,
	}
	return tr, nil
}

// QUIC connection that automatically restarts when it's used after having timed out. Needed
// since the quic-go RoundTripper doesn't have any connection management and timed out
// connections aren't restarted. This one uses EarlyConnection so we can use 0-RTT if the
// server supports it (lower latency)
type quicConnection struct {
	quic.EarlyConnection

	hostname  string
	rAddr     string
	lAddr     net.IP
	tlsConfig *tls.Config
	config    *quic.Config
	mu        sync.Mutex
	udpConn   *net.UDPConn
}

func newQuicConnection(hostname, rAddr string, lAddr net.IP, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
	connection, udpConn, err := quicDial(context.TODO(), hostname, rAddr, lAddr, tlsConfig, config)
	if err != nil {
		return nil, err
	}

	Log.WithFields(logrus.Fields{
		"protocol": "quic",
		"hostname": hostname,
		"remote":   rAddr,
		"local":    lAddr.String(),
	}).Debug("new quic connection")

	return &quicConnection{
		hostname:        hostname,
		rAddr:           rAddr,
		lAddr:           lAddr,
		tlsConfig:       tlsConfig,
		config:          config,
		udpConn:         udpConn,
		EarlyConnection: connection,
	}, nil
}

func (s *quicConnection) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.EarlyConnection.OpenStreamSync(ctx)
	if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
		Log.WithError(err).Debug("temporary fail when trying to open stream, attempting new connection")
		if err = quicRestart(s); err != nil {
			return nil, err
		}
		stream, err = s.EarlyConnection.OpenStreamSync(ctx)
	}
	return stream, err
}

func (s *quicConnection) OpenStream() (quic.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stream, err := s.EarlyConnection.OpenStream()
	if netErr, ok := err.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
		Log.WithError(err).Debug("temporary fail when trying to open stream, attempting new connection")
		if err = quicRestart(s); err != nil {
			return nil, err
		}
		stream, err = s.EarlyConnection.OpenStream()
	}
	return stream, err
}

func (s *quicConnection) NextConnection(context.Context) (quic.Connection, error) {
	return nil, errors.New("not implemented")
}

func quicRestart(s *quicConnection) error {
	// Try to open a new connection, but clean up our mess before we do so
	// This function should be called with the quicConnection locked, but lock checking isn't provided
	// in golang; the issue was closed with "Won't fix"
	_ = s.EarlyConnection.CloseWithError(DOQNoError, "")

	// We need to close the UDP socket ourselves as we own the socket not the quic-go module
	// c.f. https://github.com/quic-go/quic-go/issues/1457
	if s.udpConn != nil {
		_ = s.udpConn.Close()
		s.udpConn = nil
	}
	Log.WithFields(logrus.Fields{
		"protocol": "quic",
		"hostname": s.hostname,
		"local":    s.lAddr.String(),
		"remote":   s.rAddr,
	}).Debug("attempt reconnect")
	var err error
	var earlyConn quic.EarlyConnection
	earlyConn, s.udpConn, err = quicDial(context.TODO(), s.hostname, s.rAddr, s.lAddr, s.tlsConfig, s.config)
	if err != nil || s.udpConn == nil {
		Log.WithFields(logrus.Fields{
			"protocol": "quic",
			"address":  s.hostname,
			"local":    s.lAddr.String(),
		}).WithError(err).Error("couldn't restart quic connection")
		return err
	}
	Log.WithFields(logrus.Fields{
		"protocol": "quic",
		"address":  s.hostname,
		"local":    s.lAddr.String(),
		"rAddr":    s.rAddr,
	}).Debug("restarted quic connection")

	s.EarlyConnection = earlyConn
	return nil
}

func quicDial(ctx context.Context, hostname, rAddr string, lAddr net.IP, tlsConfig *tls.Config, config *quic.Config) (quic.EarlyConnection, *net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", rAddr)
	if err != nil {
		Log.WithError(err).Debug("couldn't resolve remote addr (" + rAddr + ") for UDP quic client")
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lAddr, Port: 0})
	if err != nil {
		Log.WithError(err).Debug("couldn't listen on UDP socket on local address [" + lAddr.String() + "]")
		return nil, nil, err
	}
	// use DialEarly so that we attempt to use 0-RTT DNS queries, it's lower latency (if the server supports it)
	earlyConn, err := quic.DialEarly(ctx, udpConn, udpAddr, tlsConfig, config)
	if err != nil {
		// don't leak filehandles / sockets; if we got here udpConn must exist
		_ = udpConn.Close()
		Log.WithError(err).Debug("couldn't dial quic early connection")
		return nil, nil, err
	}
	return earlyConn, udpConn, nil
}
