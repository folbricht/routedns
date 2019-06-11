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

	router := NewRouter()
	router.Add("", "MX", "", r1)
	router.Add("", "", "", r2)

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

func TestRouterName(t *testing.T) {
	r1 := new(TestResolver)
	r2 := new(TestResolver)
	q := new(dns.Msg)
	var ci ClientInfo

	router := NewRouter()
	router.Add(`\.acme\.test\.$`, "", "", r1)
	router.Add("", "", "", r2)

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

	router := NewRouter()
	router.Add("", "", "192.168.1.100/32", r1)
	router.Add("", "", "", r2)

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
