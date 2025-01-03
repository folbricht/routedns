package rdns

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrNoResult             = errors.New("requested RR not found")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrRRSigNotAvailable    = errors.New("RRSIG does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
	ErrDelegationChain      = errors.New("AuthChain has no Delegations")
)

type RRSet struct {
	RrSet []dns.RR
	RrSig *dns.RRSIG
}

type SignedZone struct {
	Zone         string
	Dnskey       *RRSet
	Ds           *RRSet
	ParentZone   *SignedZone
	PubKeyLookup map[uint16]*dns.DNSKEY
}

type AuthenticationChain struct {
	DelegationChain []SignedZone
}

func NewSignedRRSet() *RRSet {
	return &RRSet{
		RrSet: make([]dns.RR, 0),
	}
}

func NewSignedZone(domainName string) *SignedZone {
	return &SignedZone{
		Zone:   domainName,
		Ds:     &RRSet{},
		Dnskey: &RRSet{},
	}
}

func NewAuthenticationChain() *AuthenticationChain {
	return &AuthenticationChain{}
}

func (z *SignedZone) checkHasDnskeys() bool {
	return len(z.Dnskey.RrSet) > 0
}

func (sRRset *RRSet) IsSigned() bool {
	return sRRset.RrSig != nil
}

func (sRRset *RRSet) IsEmpty() bool {
	return len(sRRset.RrSet) < 1
}

func (z SignedZone) lookupPubKey(keyTag uint16) *dns.DNSKEY {
	return z.PubKeyLookup[keyTag]
}

func (z SignedZone) addPubKey(k *dns.DNSKEY) {
	z.PubKeyLookup[k.KeyTag()] = k
}

func removeRRSIGs(response *dns.Msg) *dns.Msg {
	var filteredAnswers []dns.RR
	filteredResponse := response.Copy()
	for _, rr := range filteredResponse.Answer {
		if _, isRRSIG := rr.(*dns.RRSIG); !isRRSIG {
			filteredAnswers = append(filteredAnswers, rr)
		}
	}

	filteredResponse.Answer = filteredAnswers
	return filteredResponse
}

func setDNSSECdo(q *dns.Msg) *dns.Msg {
	if q.IsEdns0() == nil {
		q.SetEdns0(1024, true)
	}
	q.IsEdns0().SetDo()
	return q
}

func newQuery(qname string, qtype uint16) *dns.Msg {
	dnsMessage := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
	}
	dnsMessage.SetEdns0(4096, true)
	dnsMessage.SetQuestion(qname, qtype)
	return dnsMessage
}

func getRRset(qname string, qtype uint16, resolver Resolver) (*RRSet, error) {
	q := newQuery(qname, qtype)
	r, err := doQuery(q, resolver)
	if err != nil {
		log.Printf("cannot lookup %v", err)
		return nil, err
	}

	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s\n", qName(q))
		return nil, ErrNoResult
	}
	return extractRRset(r)
}

func extractRRset(r *dns.Msg) (*RRSet, error) {
	result := NewSignedRRSet()
	if r.Answer == nil {
		return result, nil
	}

	result.RrSet = make([]dns.RR, 0, len(r.Answer))
	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			result.RrSig = t
		case *dns.DNSKEY, *dns.DS, *dns.A, *dns.AAAA:
			result.RrSet = append(result.RrSet, rr)
		}
	}
	return result, nil
}

func doQuery(q *dns.Msg, resolver Resolver) (*dns.Msg, error) {
	r, err := resolver.Resolve(q, ClientInfo{})
	if err != nil {
		return nil, err
	}
	if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
		return r, err
	}
	return nil, err
}

func queryDelegation(domainName string, resolver Resolver) (*SignedZone, error) {
	signedZone := NewSignedZone(domainName)

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	defer close(errCh)

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		signedZone.Dnskey, err = getRRset(domainName, dns.TypeDNSKEY, resolver)
		if err != nil {
			errCh <- err
			return
		}
		signedZone.PubKeyLookup = make(map[uint16]*dns.DNSKEY)
		for _, rr := range signedZone.Dnskey.RrSet {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[%v] panic occurred: %v", domainName, r)
				}
			}()
			signedZone.addPubKey(rr.(*dns.DNSKEY))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		signedZone.Ds, err = getRRset(domainName, dns.TypeDS, resolver)
		if err != nil {
			log.Printf("DS query failed for %v: %v", domainName, err)
		}
	}()

	wg.Wait()
	if len(errCh) > 0 {
		return nil, <-errCh
	}

	return signedZone, nil
}

func (authChain *AuthenticationChain) Populate(domainName string, resolver Resolver) error {
	qnameComponents := strings.Split(domainName, ".")
	zonesToVerify := len(qnameComponents)

	authChain.DelegationChain = make([]SignedZone, zonesToVerify)
	var wg sync.WaitGroup
	errCh := make(chan error, zonesToVerify)
	defer close(errCh)

	for i := 0; i < zonesToVerify; i++ {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[i:], "."))
		wg.Add(1)

		go func(index int, zone string) {
			defer wg.Done()
			delegation, err := queryDelegation(zone, resolver)
			if err != nil {
				errCh <- err
				return
			}
			authChain.DelegationChain[index] = *delegation
			if index > 0 {
				authChain.DelegationChain[index-1].ParentZone = delegation
			}
		}(i, zoneName)
	}

	wg.Wait()
	if len(errCh) > 0 {
		return <-errCh
	}

	return nil
}

func (authChain *AuthenticationChain) Verify(answerRRset *RRSet) error {
	zones := authChain.DelegationChain
	if len(zones) == 0 {
		return ErrDelegationChain
	}

	signedZone := authChain.DelegationChain[0]
	if !signedZone.checkHasDnskeys() {
		return ErrDnskeyNotAvailable
	}

	err := signedZone.verifyRRSIG(answerRRset)
	if err != nil {
		return ErrInvalidRRsig
	}

	for _, signedZone := range authChain.DelegationChain {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[AuthChain] panic occurred: %v", err)
			}
		}()

		if signedZone.Dnskey.IsEmpty() {
			return ErrDnskeyNotAvailable
		}

		err := signedZone.verifyRRSIG(signedZone.Dnskey)
		if err != nil {
			return ErrRrsigValidationError
		}

		if signedZone.ParentZone != nil {

			if signedZone.Ds.IsEmpty() {
				return ErrDsNotAvailable
			}

			err := signedZone.ParentZone.verifyRRSIG(signedZone.Ds)
			if err != nil {
				return ErrRrsigValidationError
			}
			err = signedZone.verifyDS(signedZone.Ds.RrSet)
			if err != nil {
				return ErrDsInvalid
			}
		}
	}
	return nil
}

func (z SignedZone) verifyRRSIG(signedRRset *RRSet) (err error) {
	if !signedRRset.IsSigned() {
		return ErrRRSigNotAvailable
	}

	key := z.lookupPubKey(signedRRset.RrSig.KeyTag)
	if key == nil {
		return ErrDnskeyNotAvailable
	}

	err = signedRRset.RrSig.Verify(key, signedRRset.RrSet)
	if err != nil {
		return err
	}

	if !signedRRset.RrSig.ValidityPeriod(time.Now()) {
		return ErrRrsigValidityPeriod
	}
	return nil
}

func (z SignedZone) verifyDS(dsRrset []dns.RR) (err error) {
	for _, rr := range dsRrset {
		ds := rr.(*dns.DS)
		if ds.DigestType != dns.SHA256 {
			continue
		}

		parentDsDigest := strings.ToUpper(ds.Digest)
		key := z.lookupPubKey(ds.KeyTag)
		if key == nil {
			return ErrDnskeyNotAvailable
		}
		dsDigest := strings.ToUpper(key.ToDS(ds.DigestType).Digest)
		if parentDsDigest == dsDigest {
			return nil
		}
		return ErrDsInvalid
	}
	return ErrUnknownDsDigestType
}
