package rdns

import (
	"fmt"
	"sync"

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

func setDoFlag(q *dns.Msg) {
	var edns *dns.OPT

	// Check if there's already an EDNS record in the Extra section
	for _, extra := range q.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			edns = opt
			break
		}
	}

	if edns == nil {
		edns = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		q.Extra = append(q.Extra, edns)
	}

	// Set the DO flag and the UDP size on the EDNS record
	edns.SetDo()
	edns.SetUDPSize(1024)
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
	setDoFlag(q)

	k := dns.Msg{}
	k.SetQuestion(qName(q), 48) // 48=TypeDNSKEY

	var wg sync.WaitGroup
	results := make(chan *dns.Msg, 2) // Buffer size of 2 for A and DNSKEY responses
	errors := make(chan error, 2)

	// A record query
	wg.Add(1)
	go func() {
		defer wg.Done()
		response, err := d.resolver.Resolve(q, ci)
		if err != nil {
			errors <- fmt.Errorf("a query error: %v", err)
			return
		}
		results <- response
	}()

	// DNSKEY query
	wg.Add(1)
	go func() {
		defer wg.Done()
		response, err := d.resolver.Resolve(&k, ci)
		if err != nil {
			errors <- fmt.Errorf("DNSKEY query error: %v", err)
			return
		}
		results <- response
	}()

	wg.Wait()
	close(results)
	close(errors)

	var aResponse, dnskeyResponse *dns.Msg
	for res := range results {
		switch res.Question[0].Qtype {
		case dns.TypeA, dns.TypeAAAA:
			aResponse = res
		case dns.TypeDNSKEY:
			dnskeyResponse = res
		}
	}

	for err := range errors {
		return nil, err
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
