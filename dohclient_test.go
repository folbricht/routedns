package rdns

import (
	"context"
	"expvar"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestDoHClientSimplePOST(t *testing.T) {
	d, err := NewDoHClient("test-doh", "https://1.1.1.1/dns-query{?dns}", DoHClientOptions{Method: "POST"})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDoHClientSimpleGET(t *testing.T) {
	d, err := NewDoHClient("test-doh", "https://cloudflare-dns.com/dns-query{?dns}", DoHClientOptions{Method: "GET"})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

func TestDoHTcpTransportIdleTimeoutDefault(t *testing.T) {
	tr, err := dohTcpTransport(DoHClientOptions{})
	require.NoError(t, err)
	httpTransport := tr.(*http.Transport)
	require.Equal(t, defaultDoHIdleTimeout, httpTransport.IdleConnTimeout)
}

func TestDoHTcpTransportIdleTimeoutConfigured(t *testing.T) {
	tr, err := dohTcpTransport(DoHClientOptions{IdleTimeout: 2 * time.Minute})
	require.NoError(t, err)
	httpTransport := tr.(*http.Transport)
	require.Equal(t, 2*time.Minute, httpTransport.IdleConnTimeout)
}

func TestDoHQuicTransportIdleTimeoutDefault(t *testing.T) {
	tr, err := dohQuicTransport("https://example.com/dns-query", DoHClientOptions{})
	require.NoError(t, err)
	http3Transport := tr.(*http3.Transport)
	// When not configured, MaxIdleTimeout should not be set (zero value)
	// The quic-go library will use its own default
	require.Equal(t, time.Duration(0), http3Transport.QUICConfig.MaxIdleTimeout)
}

func TestDoHQuicTransportIdleTimeoutConfigured(t *testing.T) {
	tr, err := dohQuicTransport("https://example.com/dns-query", DoHClientOptions{IdleTimeout: 2 * time.Minute})
	require.NoError(t, err)
	http3Transport := tr.(*http3.Transport)
	require.Equal(t, 2*time.Minute, http3Transport.QUICConfig.MaxIdleTimeout)
}

func TestDoHClientIdleTimeoutNegative(t *testing.T) {
	_, err := NewDoHClient("test-doh", "https://example.com/dns-query", DoHClientOptions{IdleTimeout: -1 * time.Second})
	require.Error(t, err)
	require.Contains(t, err.Error(), "idle-timeout must not be negative")
}

// TestDoHClient0RTTOptions covers the combinations of enable-0rtt, transport,
// method and address. Only a QUIC transport with a GET-capable URL template can
// actually use 0-RTT; everything else used to be accepted and then silently not
// use it, so those are now config errors.
func TestDoHClient0RTTOptions(t *testing.T) {
	const (
		templated = "https://example.com/dns-query{?dns}"
		plain     = "https://example.com/dns-query"
	)
	tests := []struct {
		name       string
		endpoint   string
		opt        DoHClientOptions
		wantMethod string // when set, construction must succeed with this method
		wantErr    string // when set, the error must contain this
	}{
		{
			name:       "0rtt defaults the method to GET",
			endpoint:   templated,
			opt:        DoHClientOptions{Use0RTT: true, Transport: "quic"},
			wantMethod: "GET",
		},
		{
			name:       "0rtt with an explicit GET",
			endpoint:   templated,
			opt:        DoHClientOptions{Use0RTT: true, Transport: "quic", Method: "GET"},
			wantMethod: "GET",
		},
		{
			name:     "0rtt with an explicit POST is contradictory",
			endpoint: templated,
			opt:      DoHClientOptions{Use0RTT: true, Transport: "quic", Method: "POST"},
			wantErr:  "enable-0rtt requires method 'GET'",
		},
		{
			name:     "0rtt needs a URL template to build a GET from",
			endpoint: plain,
			opt:      DoHClientOptions{Use0RTT: true, Transport: "quic"},
			wantErr:  "'{?dns}'",
		},
		{
			name:     "0rtt does not exist on the tcp transport",
			endpoint: templated,
			opt:      DoHClientOptions{Use0RTT: true, Transport: "tcp"},
			wantErr:  "enable-0rtt requires transport 'quic', have 'tcp'",
		},
		{
			name:     "0rtt does not exist on the default transport",
			endpoint: templated,
			opt:      DoHClientOptions{Use0RTT: true},
			wantErr:  "enable-0rtt requires transport 'quic', have 'tcp'",
		},
		{
			name:       "without 0rtt the method still defaults to POST",
			endpoint:   plain,
			opt:        DoHClientOptions{},
			wantMethod: "POST",
		},
		{
			name:       "without 0rtt a plain address and GET are still allowed",
			endpoint:   plain,
			opt:        DoHClientOptions{Method: "GET"},
			wantMethod: "GET",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDoHClient("test-doh", tc.endpoint, tc.opt)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantMethod, d.opt.Method)
		})
	}
}

// TestDoHClient0RTTOpcode verifies the method selection inside buildGetRequest:
// only opcodes that are safe to replay may be sent as 0-RTT data.
func TestDoHClient0RTTOpcode(t *testing.T) {
	d, err := NewDoHClient("test-doh", "https://example.com/dns-query{?dns}", DoHClientOptions{
		Method:    "GET",
		Transport: "quic",
		Use0RTT:   true,
	})
	require.NoError(t, err)

	// Only replayable opcodes may be sent in 0-RTT data, everything else has to
	// wait for the handshake to complete.
	for _, tc := range []struct {
		opcode int
		method string
	}{
		{dns.OpcodeQuery, http3.MethodGet0RTT},
		{dns.OpcodeNotify, http3.MethodGet0RTT},
		{dns.OpcodeUpdate, http.MethodGet},
		{dns.OpcodeStatus, http.MethodGet},
	} {
		t.Run(dns.OpcodeToString[tc.opcode], func(t *testing.T) {
			req, err := d.buildRequest(context.Background(), []byte{0, 0}, tc.opcode)
			require.NoError(t, err)
			require.Equal(t, tc.method, req.Method)
		})
	}
}

func TestReadBoundedBody(t *testing.T) {
	t.Run("under limit", func(t *testing.T) {
		b, err := readBoundedBody(strings.NewReader("hello"), 10)
		require.NoError(t, err)
		require.Equal(t, []byte("hello"), b)
	})
	t.Run("at limit", func(t *testing.T) {
		b, err := readBoundedBody(strings.NewReader(strings.Repeat("x", 10)), 10)
		require.NoError(t, err)
		require.Len(t, b, 10)
	})
	t.Run("over limit", func(t *testing.T) {
		_, err := readBoundedBody(strings.NewReader(strings.Repeat("x", 11)), 10)
		require.ErrorIs(t, err, errResponseTooLarge)
	})
}

// TestDoHClientResponseSizeLimit verifies that the DoH client bounds the upstream
// response body before parsing, so a malicious upstream returning an oversized
// body is rejected cleanly rather than buffered in full. See issue #555.
func TestDoHClientResponseSizeLimit(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("healthy.test.", dns.TypeA)

	healthy := new(dns.Msg)
	healthy.SetReply(q)
	rr, err := dns.NewRR("healthy.test. 3600 IN A 6.6.6.6")
	require.NoError(t, err)
	healthy.Answer = []dns.RR{rr}
	healthyWire, err := healthy.Pack()
	require.NoError(t, err)

	tests := []struct {
		name    string
		body    []byte
		wantErr error // when set, Resolve must return an error matching it
		wantOK  bool  // when true, Resolve must succeed with an answer
	}{
		{name: "healthy", body: healthyWire, wantOK: true},
		{name: "oversized", body: make([]byte, maxDoHResponseSize+1024), wantErr: errResponseTooLarge},
		{name: "not a dns message", body: []byte("definitely not a valid DNS wire message")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/dns-message")
				_, _ = w.Write(tc.body)
			}))
			defer srv.Close()

			d, err := NewDoHClient("test-doh-limit", srv.URL+"/dns-query", DoHClientOptions{Method: "POST"})
			require.NoError(t, err)

			a, err := d.Resolve(q, ClientInfo{})
			switch {
			case tc.wantOK:
				require.NoError(t, err)
				require.NotEmpty(t, a.Answer)
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
				// The oversized rejection must be reflected in the metrics.
				v := d.metrics.err.Get("toolarge")
				require.NotNil(t, v)
				require.Equal(t, int64(1), v.(*expvar.Int).Value())
			default:
				require.Error(t, err)
			}
		})
	}
}
