package rdns

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/jtacoma/uritemplates"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// DoHClientOptions contains options used by the DNS-over-HTTP resolver.
type DoHClientOptions struct {
	// Query method, either GET or POST. If empty, POST is used.
	Method string

	TLSConfig *tls.Config
}

// DoHClient is a DNS-over-HTTP resolver with support fot HTTP/2.
type DoHClient struct {
	endpoint string
	template *uritemplates.UriTemplate
	client   *http.Client
	opt      DoHClientOptions
}

var _ Resolver = &DoHClient{}

// NewDoHClient instantiates a new DNS-over-HTTPS resolver.
func NewDoHClient(endpoint string, opt DoHClientOptions) (*DoHClient, error) {
	// Parse the URL template
	template, err := uritemplates.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	// HTTP transport for this client
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       opt.TLSConfig,
		DisableCompression:    true,
		ResponseHeaderTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	// If we're using a custom tls.Config, HTTP2 isn't enabled by default in
	// the HTTP library. Turn it on for this transport.
	if tr.TLSClientConfig != nil {
		if err := http2.ConfigureTransport(tr); err != nil {
			return nil, err
		}
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
		endpoint: endpoint,
		template: template,
		client:   client,
		opt:      opt,
	}, nil
}

// Resolve a DNS query.
func (d *DoHClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := Log.WithFields(logrus.Fields{
		"client":   ci.SourceIP,
		"qname":    qName(q),
		"resolver": d.endpoint,
		"protocol": "doh",
		"method":   d.opt.Method,
	})
	log.Debug("querying upstream resolver")
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
		return nil, err
	}
	// The URL could be a template. Process it without values since POST doesn't use variables in the URL.
	u, err := d.template.Expand(map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return responseFromHTTP(resp)
}

// ResolveGET resolves a DNS query via DNS-over-HTTP using the GET method.
func (d *DoHClient) ResolveGET(q *dns.Msg) (*dns.Msg, error) {
	// Pack the DNS query into wire format
	b, err := q.Pack()
	if err != nil {
		return nil, err
	}
	// Encode the query as base64url without padding
	b64 := base64.RawURLEncoding.EncodeToString(b)

	// The URL must be a template. Process it with the "dns" param containing the encoded query.
	u, err := d.template.Expand(map[string]interface{}{"dns": b64})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return responseFromHTTP(resp)
}

func (d *DoHClient) String() string {
	return fmt.Sprintf("DoH-%s(%s)", d.opt.Method, d.endpoint)
}

// Check the HTTP response status code and parse out the response DNS message.
func responseFromHTTP(resp *http.Response) (*dns.Msg, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	rb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	a := new(dns.Msg)
	err = a.Unpack(rb)
	return a, err
}
