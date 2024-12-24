package rdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// The DNSSEC enforcer will upgrade DNS queries to also request DNSSEC and only forwards DNSSEC validated responses
type DNSSECenforcer struct {
	id       string
	resolver Resolver
}

var _ Resolver = &DNSSECenforcer{}

func NewDNSSECenforcer(id string, resolver Resolver) *DNSSECenforcer {
	return &DNSSECenforcer{id: id, resolver: resolver}
}

// Validate DNSSEC using DNSKEY and RRSIG
func validateDNSSEC(aResponse, dnskeyResponse *dns.Msg) error {
	dnskeys := []dns.RR{}
	for _, rr := range dnskeyResponse.Answer {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			dnskeys = append(dnskeys, rr)
		}
	}

	// Extract RRSIG from the A response
	rrsig := &dns.RRSIG{}
	for _, rr := range aResponse.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && (sig.TypeCovered == dns.TypeA || sig.TypeCovered == dns.TypeAAAA) {
			rrsig = sig
			break
		}
	}

	rrset := []dns.RR{}
	for _, rr := range aResponse.Answer {
		if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {
			rrset = append(rrset, rr)
		}
	}

	if rrsig == nil || len(dnskeys) == 0 {
		return fmt.Errorf("missing RRSIG or DNSKEY")
	}

	// Perform validation
	for _, dnskey := range dnskeys {
		if key, ok := dnskey.(*dns.DNSKEY); ok {
			if key.KeyTag() != rrsig.KeyTag {
				continue
			}
			err := rrsig.Verify(key, rrset)
			if err == nil {
				Log.Debug("DNSSEC validated")
				return nil
			}
		}
	}
	return fmt.Errorf("validation failed for all DNSKEYs")
}

func removeRRSIGs(response *dns.Msg) *dns.Msg {
	// Create a new message to store the filtered response
	filteredResponse := response.Copy()

	// Filter out any RRSIG records from the Answer section
	var filteredAnswers []dns.RR
	for _, rr := range filteredResponse.Answer {
		if _, isRRSIG := rr.(*dns.RRSIG); !isRRSIG {
			filteredAnswers = append(filteredAnswers, rr)
		}
	}

	// Set the filtered Answer section
	filteredResponse.Answer = filteredAnswers
	return filteredResponse
}

// Resolve a DNS query with DNSSEC verification. This requires sending a second DNS request for the DNSKEY. Also for the initial DNS query, the DO flag is set.
func (d *DNSSECenforcer) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	// Set DNSSEC Do flag
	if q.IsEdns0() == nil {
		q.SetEdns0(1024, true)
	} else {
		q.IsEdns0().SetDo()
	}

	// Prepare DNSKEY query
	k := new(dns.Msg)
	k.SetQuestion(qName(q), dns.TypeDNSKEY)

	results := make(chan *dns.Msg, 2)
	errors := make(chan error, 2)
	for _, m := range []*dns.Msg{q, k} {
		go func(query *dns.Msg) {
			res, err := d.resolver.Resolve(query, ci)
			if err != nil {
				errors <- err
				return
			}
			results <- res
		}(m)
	}

	var aResponse, dnskeyResponse *dns.Msg
	for i := 0; i < 2; i++ {
		select {
		case res := <-results:
			switch res.Question[0].Qtype {
			case dns.TypeA, dns.TypeAAAA:
				aResponse = res
			case dns.TypeDNSKEY:
				dnskeyResponse = res
			}
		case err := <-errors:
			return nil, fmt.Errorf("query error: %v", err)
		}
	}

	if err := validateDNSSEC(aResponse, dnskeyResponse); err != nil {
		Log.Error("DNSSEC validation failed:", err)
		return nil, err
	}
	return removeRRSIGs(aResponse), nil
}

func (d *DNSSECenforcer) String() string {
	return d.id
}
