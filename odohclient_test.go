package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestODOHClientSimple(t *testing.T) {
	d, err := NewODoHClient("test-odoh", "https://odoh-noads-nl.alekberg.net/proxy", "https://odoh.cloudflare-dns.com/dns-query", "", DoHClientOptions{})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}
