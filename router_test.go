package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRouterType(t *testing.T) {
	r1 := new(TestResolver)
	r2 := new(TestResolver)
	q := new(dns.Msg)
	var ci ClientInfo

	route1, _ := NewRoute("", "", []string{"MX"}, nil, "", "", "", "", "", "", r1)
	route2, _ := NewRoute("", "", nil, nil, "", "", "", "", "", "", r2)

	router := NewRouter("my-router")
	router.Add(route1, route2)

	// Not MX record, should go to r2
	q.SetQuestion("acme.test.", dns.TypeA)
	_, err := router.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 0, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())

	// MX record, should go to r1
	q.SetQuestion("acme.test.", dns.TypeMX)
	_, err = router.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
}

func TestRouterClass(t *testing.T) {
	r1 := new(TestResolver)
	r2 := new(TestResolver)
	q := new(dns.Msg)
	var ci ClientInfo

	route1, _ := NewRoute("", "ANY", nil, nil, "", "", "", "", "", "", r1)
	route2, _ := NewRoute("", "", nil, nil, "", "", "", "", "", "", r2)

	router := NewRouter("my-router")
	router.Add(route1, route2)

	// ClassINET question, should go to r2
	q.SetQuestion("acme.test.", dns.TypeA)
	_, err := router.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 0, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())

	// ClassAny should go to r1
	q.Question = make([]dns.Question, 1)
	q.Question[0] = dns.Question{"miek.nl.", dns.TypeMX, dns.ClassANY}
	_, err = router.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
}

func TestRouterName(t *testing.T) {
	r1 := new(TestResolver)
	r2 := new(TestResolver)
	q := new(dns.Msg)
	var ci ClientInfo

	route1, _ := NewRoute(`\.acme\.test\.$`, "", nil, nil, "", "", "", "", "", "", r1)
	route2, _ := NewRoute("", "", nil, nil, "", "", "", "", "", "", r2)

	router := NewRouter("my-router")
	router.Add(route1, route2)

	// No match, should go to r2
	q.SetQuestion("bla.test.", dns.TypeA)
	_, err := router.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 0, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())

	// Match, should go to r1
	q.SetQuestion("x.acme.test.", dns.TypeMX)
	_, err = router.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
}

func TestRouterSource(t *testing.T) {
	r1 := new(TestResolver)
	r2 := new(TestResolver)
	q := new(dns.Msg)
	q.SetQuestion("acme.test.", dns.TypeA)

	route1, _ := NewRoute("", "", nil, nil, "", "", "192.168.1.100/32", "", "", "", r1)
	route2, _ := NewRoute("", "", nil, nil, "", "", "", "", "", "", r2)

	router := NewRouter("my-router")
	router.Add(route1, route2)

	// No match, should go to r2
	_, err := router.Resolve(q, ClientInfo{SourceIP: net.ParseIP("192.168.1.50")})
	require.NoError(t, err)
	require.Equal(t, 0, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())

	// Match, should go to r1
	_, err = router.Resolve(q, ClientInfo{SourceIP: net.ParseIP("192.168.1.100")})
	require.NoError(t, err)
	require.Equal(t, 1, r1.HitCount())
	require.Equal(t, 1, r2.HitCount())
}
