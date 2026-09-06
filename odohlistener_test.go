package rdns

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// An oblivious query is answered by the upstream resolver and counted under the
// listener id, the same place the plain DoH path counts its queries.
func TestODoHListenerQuery(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			require.Equal(t, "odoh", ci.Protocol)
			a := new(dns.Msg)
			a.SetReply(q)
			return a, nil
		},
	}
	l, err := NewODoHListener("test-odoh-listener", ":8443", ODoHListenerOptions{TLSConfig: new(tls.Config)}, upstream)
	require.NoError(t, err)

	metrics := l.doh.metrics
	queries := metrics.query.Value()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	w := postObliviousQuery(t, l, q)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 1, upstream.HitCount())
	require.Equal(t, queries+1, metrics.query.Value())
	require.Equal(t, "1", metrics.response.Get("NOERROR").String())
}

// A dropped query (a nil response from the chain) is answered with no message
// and counted as a drop rather than as a response.
func TestODoHListenerDrop(t *testing.T) {
	l, err := NewODoHListener("test-odoh-drop", ":8443", ODoHListenerOptions{TLSConfig: new(tls.Config)}, NewDropResolver("drop"))
	require.NoError(t, err)

	metrics := l.doh.metrics
	drops := metrics.drop.Value()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	w := postObliviousQuery(t, l, q)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Empty(t, w.Body.Bytes())
	require.Equal(t, drops+1, metrics.drop.Value())
}

// Encrypts a query for the listener's own key pair and hands it to the query
// handler, the way an ODoH proxy would.
func postObliviousQuery(t *testing.T, l *ODoHListener, q *dns.Msg) *httptest.ResponseRecorder {
	t.Helper()
	packed, err := q.Pack()
	require.NoError(t, err)
	encrypted, _, err := l.odohKeyPair.Config.Contents.EncryptQuery(odoh.CreateObliviousDNSQuery(packed, 0))
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, ODOH_QUERY_PATH, bytes.NewReader(encrypted.Marshal()))
	r.Header.Set("Content-Type", ODOH_CONTENT_TYPE)
	w := httptest.NewRecorder()
	l.ODoHqueryHandler(w, r)
	return w
}
