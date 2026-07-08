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

func TestValidateResponseQuestion(t *testing.T) {
	query := func(name string, qtype uint16) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, qtype)
		return q
	}

	tests := []struct {
		name    string
		q, a    *dns.Msg
		wantErr bool
	}{
		{
			name: "matching question",
			q:    query("example.com.", dns.TypeA),
			a:    query("example.com.", dns.TypeA),
		},
		{
			name: "name case does not matter",
			q:    query("ExAmPlE.CoM.", dns.TypeA),
			a:    query("example.com.", dns.TypeA),
		},
		{
			name:    "name mismatch",
			q:       query("victim.example.", dns.TypeA),
			a:       query("attacker.example.", dns.TypeA),
			wantErr: true,
		},
		{
			name:    "type mismatch",
			q:       query("example.com.", dns.TypeA),
			a:       query("example.com.", dns.TypeAAAA),
			wantErr: true,
		},
		{
			name: "class mismatch",
			q:    query("example.com.", dns.TypeA),
			a: func() *dns.Msg {
				a := query("example.com.", dns.TypeA)
				a.Question[0].Qclass = dns.ClassCHAOS
				return a
			}(),
			wantErr: true,
		},
		{
			name:    "empty question in response",
			q:       query("example.com.", dns.TypeA),
			a:       new(dns.Msg),
			wantErr: true,
		},
		{
			// A query without a question can't be validated against.
			name: "empty question in query",
			q:    new(dns.Msg),
			a:    query("example.com.", dns.TypeA),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateResponseQuestion(test.q, test.a)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
