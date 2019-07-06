package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestReplace(t *testing.T) {
	var ci ClientInfo
	var actualQueryName string
	r := &TestResolver{
		ResolveFunc: func(req *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			actualQueryName = req.Question[0].Name
			a := new(dns.Msg)
			a.SetReply(req)
			a.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   req.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    3600,
					},
					A: net.ParseIP("127.0.0.1"),
				},
			}
			return a, nil
		},
	}

	exp := []ReplaceOperation{
		{From: `^my\.(.*)`, To: `your.${1}`},
	}

	b, err := NewReplace(r, exp...)
	require.NoError(t, err)

	// First query without any expected modifications
	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)
	a, err := b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, "test.com.", a.Answer[0].Header().Name)
	require.Equal(t, "test.com.", actualQueryName)

	// Now with modifications. The resolved name should be replaced
	// while in the reponse we should see the original name again.
	q.SetQuestion("my.test.com.", dns.TypeA)
	a, err = b.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, "my.test.com.", a.Answer[0].Header().Name)
	require.Equal(t, "my.test.com.", a.Question[0].Name)
	require.Equal(t, "your.test.com.", actualQueryName)
}
