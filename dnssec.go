package rdns

import (
	"log"
	"strings"
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

// Resolve a DNS query with DNSSEC verification. This requires sending a second DNS request for the DNSKEY. Also for the initial DNS query, the DO flag is set.
func (d *DNSSECenforcer) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	var answer *RRSet
	var response *dns.Msg
	var authChain *AuthenticationChain
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	defer close(errCh)

	wg.Add(1)
	// resolve the A query with RRSIG option
	go func() {
		defer wg.Done()
		var err error
		res, err := d.resolver.Resolve(setDNSSECdo(q), ci)
		if err != nil {
			errCh <- err
			return
		}
		response = res.Copy()
		answer, err = extractRRset(res)
		if err != nil {
			errCh <- err
			return
		}
		if answer.IsEmpty() {
			errCh <- ErrNoResult
			return
		}
		if !answer.IsSigned() {
			errCh <- ErrResourceNotSigned
			return
		}
	}()

	wg.Add(1)
	// resolve the entire DNSSEC authentication chain
	go func() {
		defer wg.Done()
		authChain = NewAuthenticationChain()
		if populateErr := authChain.Populate(qName(q), d.resolver); populateErr != nil {
			errCh <- populateErr
			return
		}
	}()

	wg.Wait()
	if len(errCh) > 0 {
		return nil, <-errCh
	}

	if err := authChain.Verify(answer); err != nil {
		return nil, err
	}

	log.Printf("Valid DNS Record Answer for %v (%v)\n", qName(q), dns.TypeA)
	//printChain(authChain)
	return removeRRSIGs(response), nil
}

func (d *DNSSECenforcer) String() string {
	return d.id
}

func printChain(authChain *AuthenticationChain) {
	log.Printf("containing the chain...\n")
	log.Printf("-----------------------CHAIN-----------------------\n")
	zones := authChain.DelegationChain
	for i, sz := range zones {

		spaces := make([]string, 0)
		for k := 0; k < i*4; k++ {
			spaces = append(spaces, " ")
		}
		spaceString := strings.Join(spaces, "")

		log.Printf("%v[Chain Level %v]\n", spaceString, i+1)
		log.Printf("%v\tZone      : %v\n", spaceString, sz.Zone)
		log.Printf("%v\tDNSKEY    : (RRSET)\n", spaceString)
		rrset := sz.Dnskey.RrSet
		for _, s := range rrset {
			log.Printf("%v\t\t%v\n", spaceString, s.String())
		}
		log.Printf("%v\tDNSKEY    : (RRSIG)\n", spaceString)
		log.Printf("%v\t\t%v\n", spaceString, sz.Dnskey.RrSig)

		if sz.Ds != nil {
			dsset := sz.Ds.RrSet
			log.Printf("%v\tDS        : (RRSET)\n", spaceString)
			for _, s := range dsset {
				log.Printf("%v\t\t%v\n", spaceString, s.String())
			}
			log.Printf("%v\tDS        : (RRSIG)\n", spaceString)
			log.Printf("%v\t\t%v\n", spaceString, sz.Ds.RrSig)
		}
		log.Printf("%v\tKeys      :\n", spaceString)
		for k, v := range sz.PubKeyLookup {
			log.Printf("%v\t\t %v : %v\n", spaceString, k, v)
		}
		log.Println("")
	}
	log.Printf("-------------------END CHAIN-----------------------\n")
}
