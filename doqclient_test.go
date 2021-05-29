package rdns

import (
	"testing"

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
