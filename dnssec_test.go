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

func TestDNSSECValidatorRejectsUnauthenticatedEmptyDS(t *testing.T) {
	// Upstream returns unsigned data and an empty DS response with no
	// NSEC/NSEC3 proof. This is indistinguishable from an on-path attacker
	// stripping RRSIGs and must SERVFAIL rather than pass through.
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR("insecure.example. 300 IN A 1.2.3.4")
				a.Answer = []dns.RR{rr}
			}
			return a, nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("insecure.example.", dns.TypeA)
	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, dns.RcodeServerFailure, answer.Rcode)
	require.Empty(t, answer.Answer)
}

func TestDNSSECValidatorString(t *testing.T) {
	upstream := &TestResolver{}
	v, err := NewDNSSECValidator("my-validator", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)
	require.Equal(t, "my-validator", v.String())
}

// dnssecResponse returns a response with DNSSEC records (RRSIG, NSEC) mixed in.
func dnssecResponse(q *dns.Msg, rcode int) *dns.Msg {
	a := new(dns.Msg)
	a.SetReply(q)
	a.Rcode = rcode

	arec, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
	rrsig, _ := dns.NewRR("example.com. 300 IN RRSIG A 8 2 300 20260401000000 20260301000000 12345 example.com. fakesig==")
	nsec, _ := dns.NewRR("example.com. 300 IN NSEC example.org. A AAAA RRSIG NSEC")
	a.Answer = []dns.RR{arec, rrsig}
	a.Ns = []dns.RR{nsec}

	// Add OPT with DO set (as upstream would)
	a.SetEdns0(4096, true)
	return a
}

func TestDNSSECValidatorQueryNotMutated(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return dnssecResponse(q, dns.RcodeRefused), nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	// Ensure the original query is not mutated
	require.Nil(t, q.IsEdns0(), "query should not have EDNS0 before Resolve")
	_, err = v.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Nil(t, q.IsEdns0(), "original query must not be mutated")
}

func TestDNSSECValidatorStripsDNSSECWithoutDO(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return dnssecResponse(q, dns.RcodeRefused), nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	// Client sends query without DO bit
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// RRSIG should be stripped from Answer
	for _, rr := range answer.Answer {
		require.NotEqual(t, dns.TypeRRSIG, rr.Header().Rrtype, "RRSIG should be stripped")
	}
	// NSEC should be stripped from Ns
	for _, rr := range answer.Ns {
		require.NotEqual(t, dns.TypeNSEC, rr.Header().Rrtype, "NSEC should be stripped")
	}
	// A record should be preserved
	require.Len(t, answer.Answer, 1)
	require.Equal(t, dns.TypeA, answer.Answer[0].Header().Rrtype)
}

func TestDNSSECValidatorPreservesDNSSECWithDO(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return dnssecResponse(q, dns.RcodeRefused), nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	// Client sends query WITH DO bit
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(4096, true)

	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// RRSIG should be preserved
	require.Len(t, answer.Answer, 2, "both A and RRSIG should be present")
	require.Len(t, answer.Ns, 1, "NSEC should be preserved")
}

func TestDNSSECValidatorPreservesQtypeRRSIG(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			a := new(dns.Msg)
			a.SetReply(q)
			a.Rcode = dns.RcodeRefused
			rrsig, _ := dns.NewRR("example.com. 300 IN RRSIG A 8 2 300 20260401000000 20260301000000 12345 example.com. fakesig==")
			a.Answer = []dns.RR{rrsig}
			return a, nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	// Client queries for RRSIG type specifically, without DO
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeRRSIG)

	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// RRSIG should NOT be stripped because it matches the query type
	require.Len(t, answer.Answer, 1)
	require.Equal(t, dns.TypeRRSIG, answer.Answer[0].Header().Rrtype)
}

func TestDNSSECValidatorRemovesOPTWithoutClientEDNS0(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return dnssecResponse(q, dns.RcodeRefused), nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	// Client sends query without EDNS0
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// OPT record should be removed since client didn't send EDNS0
	require.Nil(t, answer.IsEdns0(), "OPT should be removed when client had no EDNS0")
}

func TestDNSSECValidatorClearsDOInResponseOPT(t *testing.T) {
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			return dnssecResponse(q, dns.RcodeRefused), nil
		},
	}

	v, err := NewDNSSECValidator("test", upstream, DNSSECValidatorOptions{})
	require.NoError(t, err)

	// Client sends EDNS0 but without DO
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(4096, false)

	answer, err := v.Resolve(q, ClientInfo{})
	require.NoError(t, err)

	// OPT should be present but DO should be cleared
	opt := answer.IsEdns0()
	require.NotNil(t, opt, "OPT should be present when client sent EDNS0")
	require.False(t, opt.Do(), "DO bit should be cleared in response")
}

func TestDNSSECValidatorADNotSetOnInsecureDelegation(t *testing.T) {
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
	require.False(t, answer.AuthenticatedData, "AD should not be set on insecure delegation")
}

func TestFilterDNSSECRR(t *testing.T) {
	arec, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
	rrsig, _ := dns.NewRR("example.com. 300 IN RRSIG A 8 2 300 20260401000000 20260301000000 12345 example.com. fakesig==")
	nsec, _ := dns.NewRR("example.com. 300 IN NSEC example.org. A AAAA RRSIG NSEC")
	nsec3, _ := dns.NewRR("abc123.example.com. 300 IN NSEC3 1 0 10 AABB abc124.example.com. A AAAA RRSIG")
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}

	t.Run("strips RRSIG NSEC NSEC3", func(t *testing.T) {
		rrs := []dns.RR{arec, rrsig, nsec, nsec3}
		filtered := filterDNSSECRR(rrs, dns.TypeA)
		require.Len(t, filtered, 1)
		require.Equal(t, dns.TypeA, filtered[0].Header().Rrtype)
	})

	t.Run("preserves OPT", func(t *testing.T) {
		rrs := []dns.RR{opt, rrsig}
		filtered := filterDNSSECRR(rrs, dns.TypeA)
		require.Len(t, filtered, 1)
		_, isOPT := filtered[0].(*dns.OPT)
		require.True(t, isOPT)
	})

	t.Run("preserves records matching qtype", func(t *testing.T) {
		rrs := []dns.RR{rrsig}
		filtered := filterDNSSECRR(rrs, dns.TypeRRSIG)
		require.Len(t, filtered, 1)
	})

	t.Run("empty input", func(t *testing.T) {
		filtered := filterDNSSECRR(nil, dns.TypeA)
		require.Nil(t, filtered)
	})
}
