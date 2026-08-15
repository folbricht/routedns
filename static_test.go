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
	r, err := NewStaticResolver("test-static", opt)
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

// A response must not be modified by any query that follows it. The number of
// Extra records matters here: append grows a nil slice 1 -> 2 -> 4, so three
// records leave spare capacity for SetEdns0 to write into.
func TestStaticResolverResponseIsolation(t *testing.T) {
	tpl, err := NewEDNS0EDETemplate(dns.ExtendedErrorCodeBlocked, "blocked: {{ .Question }}")
	require.NoError(t, err)

	opt := StaticResolverOptions{
		Answer: []string{"IN A 1.2.3.4"},
		NS:     []string{"example.com. 18000 IN NS ns1.example.com."},
		Extra: []string{
			"ns1.example.com. IN A 1.1.1.1",
			"ns2.example.com. IN A 1.1.1.2",
			"ns3.example.com. IN A 1.1.1.3",
		},
		EDNS0EDETemplate: tpl,
	}
	r, err := NewStaticResolver("test-static", opt)
	require.NoError(t, err)

	resolve := func(name string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeA)
		a, err := r.Resolve(q, ClientInfo{})
		require.NoError(t, err)
		return a
	}

	edeText := func(a *dns.Msg) string {
		opt := a.IsEdns0()
		require.NotNil(t, opt)
		require.Len(t, opt.Option, 1)
		return opt.Option[0].(*dns.EDNS0_EDE).ExtraText
	}

	a1 := resolve("first.example.com.")
	require.Equal(t, "blocked: first.example.com.", edeText(a1))

	a2 := resolve("second.example.com.")
	require.Equal(t, "blocked: second.example.com.", edeText(a2))

	// The second query must have left the first response alone
	require.Equal(t, "blocked: first.example.com.", edeText(a1))
	require.Equal(t, "first.example.com.", a1.Answer[0].Header().Name)
	require.Len(t, a1.Extra, len(opt.Extra)+1)
}
