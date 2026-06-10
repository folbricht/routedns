package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestSetUDPSizeWithoutEDNS0(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	out := setUDPSize(q, 1232)

	// The returned copy must have an OPT record with the new size
	edns0 := out.IsEdns0()
	require.NotNil(t, edns0)
	require.Equal(t, uint16(1232), edns0.UDPSize())

	// The original query must not have been modified
	require.Nil(t, q.IsEdns0())
}

func TestSetUDPSizeWithEDNS0(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(512, false)

	out := setUDPSize(q, 1232)

	// The returned copy must have the updated size
	edns0 := out.IsEdns0()
	require.NotNil(t, edns0)
	require.Equal(t, uint16(1232), edns0.UDPSize())

	// The original query must keep its size
	require.Equal(t, uint16(512), q.IsEdns0().UDPSize())
}

func TestSetUDPSizeDisabled(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Size 0 leaves the query untouched
	out := setUDPSize(q, 0)
	require.Same(t, q, out)
	require.Nil(t, out.IsEdns0())
}
