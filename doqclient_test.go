package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDOQSimple(t *testing.T) {
	d, err := NewDoQClient("test-doq", "dns-unfiltered.adguard.com:8853", DoQClientOptions{})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	id := q.Id
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
	require.Equal(t, id, r.Id)
}

func TestDOQError(t *testing.T) {
	d, err := NewDoQClient("test-doq", "127.0.0.1:0", DoQClientOptions{})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("google.com.", dns.TypeA)
	id := q.Id
	_, err = d.Resolve(q, ClientInfo{})
	require.Error(t, err)
	require.Equal(t, id, q.Id) // Shouldn't touch the ID in the query
}

// A DoQ upstream that answers with a question other than the one that was
// asked must be rejected, and nothing may be stored in a cache placed in front
// of it. The QUIC stream identifies which stream carried the response, not that
// the DNS message in it answers the question. See issue #595.
func TestDOQWrongQuestionResponse(t *testing.T) {
	// Upstream that always answers for attacker.example., regardless of the query
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetQuestion("attacker.example.", dns.TypeA)
			a.Response = true
			a.Id = q.Id
			rr, err := dns.NewRR("attacker.example. 3600 IN A 6.6.6.6")
			if err != nil {
				return nil, err
			}
			a.Answer = []dns.RR{rr}
			return a, nil
		},
	}

	addr, err := getUDPLnAddress()
	require.NoError(t, err)
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	ln := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() { _ = ln.Start() }()
	defer ln.Stop()
	time.Sleep(500 * time.Millisecond)

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	client, err := NewDoQClient("test-doq-client", addr, DoQClientOptions{TLSConfig: tlsClientConfig})
	require.NoError(t, err)

	cache := NewCache("test-cache", client, CacheOptions{})

	q := new(dns.Msg)
	q.SetQuestion("victim.example.", dns.TypeA)

	// The mismatched response must not be passed on to the caller
	_, err = cache.Resolve(q.Copy(), ClientInfo{})
	require.Error(t, err)

	// Nothing should have been cached under the victim's key, so a second query
	// hits the upstream again rather than being served a poisoned entry.
	_, err = cache.Resolve(q.Copy(), ClientInfo{})
	require.Error(t, err)
	require.Equal(t, 2, upstream.HitCount())
}
