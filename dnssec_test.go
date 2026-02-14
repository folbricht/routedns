package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSSECValidatorSetsDoFlag(t *testing.T) {
	var capturedQuery *dns.Msg
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			capturedQuery = q.Copy()
			a := new(dns.Msg)
			a.SetReply(q)
			return a, nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	// Query without EDNS0 set
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = v.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// Verify DO bit was set on the query sent upstream
	require.NotNil(t, capturedQuery)
	edns0 := capturedQuery.IsEdns0()
	require.NotNil(t, edns0)
	require.True(t, edns0.Do())
}

func TestDNSSECValidatorSetsDoFlagExistingEDNS0(t *testing.T) {
	var capturedQuery *dns.Msg
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			capturedQuery = q.Copy()
			a := new(dns.Msg)
			a.SetReply(q)
			return a, nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	// Query with EDNS0 but DO not set
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(4096, false)
	_, err = v.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// Verify DO bit was enabled
	require.NotNil(t, capturedQuery)
	edns0 := capturedQuery.IsEdns0()
	require.NotNil(t, edns0)
	require.True(t, edns0.Do())
}

func TestDNSSECValidatorServfailOnFailure(t *testing.T) {
	// Upstream returns unsigned data for a domain with DS records
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeDS {
				// Return DS records to indicate DNSSEC-signed zone
				ds, _ := dns.NewRR("example.com. 3600 IN DS 12345 8 2 ABCD")
				a.Answer = []dns.RR{ds}
			} else if q.Question[0].Qtype == dns.TypeA {
				// Return unsigned A record
				rr, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
				a.Answer = []dns.RR{rr}
			}
			return a, nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, answer.Rcode)
}

func TestDNSSECValidatorLogOnlyMode(t *testing.T) {
	// Upstream returns unsigned data for a domain with DS records
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeDS {
				ds, _ := dns.NewRR("example.com. 3600 IN DS 12345 8 2 ABCD")
				a.Answer = []dns.RR{ds}
			} else if q.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
				a.Answer = []dns.RR{rr}
			}
			return a, nil
		},
	}

	v, err := NewDNSSECValidator("test-logonly", upstream, DNSSECValidatorOptions{
		LogOnly: true,
	})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	// In log-only mode, the original response should pass through (not SERVFAIL)
	require.Equal(t, dns.RcodeSuccess, answer.Rcode)
	require.Len(t, answer.Answer, 1)
}

func TestDNSSECValidatorPassthroughOnError(t *testing.T) {
	upstream := &TestResolver{
		shouldFail: true,
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = v.Resolve(q, ClientInfo{})
	require.Error(t, err)
}

func TestDNSSECValidatorInsecureDelegationPassthrough(t *testing.T) {
	// Upstream returns unsigned data for an insecure zone (no DS)
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR("insecure.example. 300 IN A 1.2.3.4")
				a.Answer = []dns.RR{rr}
			}
			// DS lookup returns empty → insecure delegation
			return a, nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("insecure.example.", dns.TypeA)
	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	// Insecure delegations should pass through
	require.Equal(t, dns.RcodeSuccess, answer.Rcode)
	require.Len(t, answer.Answer, 1)
}

func TestDNSSECValidatorString(t *testing.T) {
	upstream := &TestResolver{}
	v, err := NewDNSSECValidator("my-validator", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)
	require.Equal(t, "my-validator", v.String())
}
