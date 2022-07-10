package rdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDTLSListener(t *testing.T) {
	upstream := new(TestResolver)

	// Find a free port for the listener
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the listener
	dtlsConfig, err := DTLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)
	s := NewDTLSListener("test-dtls-server", addr, DTLSListenerOptions{DTLSConfig: dtlsConfig}, upstream)
	go s.Start()
	defer s.Stop()
	time.Sleep(time.Second)

	// Make a client talking to the listener
	dtlsClientConfig, err := DTLSClientConfig("testdata/ca.crt", "", "")
	require.NoError(t, err)
	c, err := NewDTLSClient("test-dtls-client", addr, DTLSClientOptions{DTLSConfig: dtlsClientConfig})
	require.NoError(t, err)

	// Send a query to the client. This should be proxied through the listener and hit the test resolver.
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// The upstream resolver should have seen the query
	require.Equal(t, 1, upstream.HitCount())
}
