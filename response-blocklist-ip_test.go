package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// answering builds a resolver that replies with the given addresses plus a
// CNAME, which is the shape filtering has to leave alone.
func answering(addrs ...string) Resolver {
	return &testAnswerResolver{addrs: addrs}
}

type testAnswerResolver struct{ addrs []string }

func (r *testAnswerResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	a := new(dns.Msg)
	a.SetReply(q)
	a.Answer = append(a.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: "cdn.example.net.",
	})
	for _, s := range r.addrs {
		ip := net.ParseIP(s)
		if ip4 := ip.To4(); ip4 != nil {
			a.Answer = append(a.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip4,
			})
			continue
		}
		a.Answer = append(a.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: ip,
		})
	}
	return a, nil
}
func (r *testAnswerResolver) String() string { return "test" }

func filterResolver(t *testing.T, upstream Resolver, rules ...string) *ResponseBlocklistIP {
	t.Helper()
	db, err := NewCidrDB("testlist", NewStaticLoader(rules))
	require.NoError(t, err)
	r, err := NewResponseBlocklistIP("test-rbi", upstream, ResponseBlocklistIPOptions{
		BlocklistDB: db, Filter: true,
	})
	require.NoError(t, err)
	return r
}

func ask(t *testing.T, r Resolver) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	a, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	return a
}

// Filtering keeps what does not match, in the order it arrived, and leaves
// records that carry no address alone.
func TestResponseBlocklistIPFilter(t *testing.T) {
	t.Run("nothing matches", func(t *testing.T) {
		a := ask(t, filterResolver(t, answering("1.1.1.1", "2.2.2.2"), "10.0.0.0/8"))
		require.Len(t, a.Answer, 3)
		require.Equal(t, "1.1.1.1", a.Answer[1].(*dns.A).A.String())
		require.Equal(t, "2.2.2.2", a.Answer[2].(*dns.A).A.String())
	})

	t.Run("the first one goes", func(t *testing.T) {
		a := ask(t, filterResolver(t, answering("10.0.0.1", "2.2.2.2"), "10.0.0.0/8"))
		require.Len(t, a.Answer, 2)
		require.Equal(t, dns.TypeCNAME, a.Answer[0].Header().Rrtype, "a record with no address stays")
		require.Equal(t, "2.2.2.2", a.Answer[1].(*dns.A).A.String())
	})

	t.Run("one in the middle goes", func(t *testing.T) {
		a := ask(t, filterResolver(t, answering("1.1.1.1", "10.0.0.1", "2.2.2.2"), "10.0.0.0/8"))
		require.Len(t, a.Answer, 3)
		require.Equal(t, "1.1.1.1", a.Answer[1].(*dns.A).A.String())
		require.Equal(t, "2.2.2.2", a.Answer[2].(*dns.A).A.String())
	})

	t.Run("the last one goes", func(t *testing.T) {
		a := ask(t, filterResolver(t, answering("1.1.1.1", "10.0.0.1"), "10.0.0.0/8"))
		require.Len(t, a.Answer, 2)
		require.Equal(t, "1.1.1.1", a.Answer[1].(*dns.A).A.String())
	})

	t.Run("every address goes", func(t *testing.T) {
		// Only the CNAME is left, which is not nothing, so the answer stands.
		a := ask(t, filterResolver(t, answering("10.0.0.1", "10.0.0.2"), "10.0.0.0/8"))
		require.Len(t, a.Answer, 1)
		require.Equal(t, dns.TypeCNAME, a.Answer[0].Header().Rrtype)
	})

	t.Run("nothing is left", func(t *testing.T) {
		db, err := NewCidrDB("testlist", NewStaticLoader([]string{"10.0.0.0/8"}))
		require.NoError(t, err)
		r, err := NewResponseBlocklistIP("test-rbi", &testAnswerResolver{addrs: []string{"10.0.0.1"}},
			ResponseBlocklistIPOptions{BlocklistDB: db, Filter: true})
		require.NoError(t, err)
		// Strip the CNAME by asking the upstream for addresses only.
		r.resolver = &testAddrOnlyResolver{addrs: []string{"10.0.0.1"}}
		a := ask(t, r)
		require.Equal(t, dns.RcodeNameError, a.Rcode, "an answer with everything filtered is NXDOMAIN")
	})
}

type testAddrOnlyResolver struct{ addrs []string }

func (r *testAddrOnlyResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	a := new(dns.Msg)
	a.SetReply(q)
	for _, s := range r.addrs {
		a.Answer = append(a.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(s).To4(),
		})
	}
	return a, nil
}
func (r *testAddrOnlyResolver) String() string { return "test" }
