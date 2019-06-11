package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDoTClientSimple(t *testing.T) {
	d := NewDoTClient("dns.google:853")
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}
