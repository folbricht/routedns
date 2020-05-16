package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestStaticResolver(t *testing.T) {
	opt := StaticResolverOptions{
		Answer: []string{
			"IN A 1.2.3.4",
		},
		NS: []string{
			"example.com. 18000 IN A 1.2.3.4",
			"example.com. 18000 IN AAAA ::1",
		},
		Extra: []string{
			"ns1.example.com. IN A 1.1.1.1",
		},
	}
	r, err := NewStaticResolver(opt)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("test.com.", dns.TypeA)

	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, len(opt.Answer), len(a.Answer))
	require.Equal(t, len(opt.NS), len(a.Ns))
	require.Equal(t, len(opt.Extra), len(a.Extra))
	require.Equal(t, "test.com.", a.Answer[0].Header().Name)
	require.Equal(t, "example.com.", a.Ns[0].Header().Name)
	require.Equal(t, "ns1.example.com.", a.Extra[0].Header().Name)
}
