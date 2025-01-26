package rdns

import (
	"errors"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrNoResult             = errors.New("requested RR not found")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrDsFailed             = errors.New("DS query failed")
	ErrRRSigNotAvailable    = errors.New("RRSIG does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrForgedRRsig          = errors.New("forged RRSIG header")
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

func (r *RRSet) isSigned() bool {
	return r.RrSig != nil
}

func (r *RRSet) isEmpty() bool {
	return len(r.RrSet) < 1
}

func (r *RRSet) checkHeaderIntegrity(qname string) bool {
	return r.RrSig != nil && r.RrSig.Header().Name != qname
}

func (z *SignedZone) checkHasDnskeys() bool {
	return len(z.Dnskey.RrSet) > 0
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
	m := &dns.Msg{}
	m.SetEdns0(4096, true)
	return m.SetQuestion(qname, qtype)
}

func getRRset(qname string, qtype uint16, resolver Resolver, ci ClientInfo) (*RRSet, error) {
	q := newQuery(qname, qtype)
	r, err := doQuery(q, resolver, ci)
	if err != nil || r == nil {
		return nil, err
	}
	return extractRRset(r)
}

func extractRRset(r *dns.Msg) (*RRSet, error) {
	result := &RRSet{}
	if r.Answer == nil {
		return result, nil
	}

	result.RrSet = []dns.RR{}
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

func doQuery(q *dns.Msg, resolver Resolver, ci ClientInfo) (*dns.Msg, error) {
	r, err := resolver.Resolve(q, ci)
	if err != nil {
		return nil, err
	}
	if r.Rcode == dns.RcodeNameError {
		Log.Info("no such domain", "info", qName(r))
		return nil, ErrNoResult
	}
	if r == nil || r.Rcode == dns.RcodeSuccess {
		return r, nil
	}
	return nil, ErrInvalidRRsig
}

func queryDelegation(domainName string, resolver Resolver, ci ClientInfo) (*SignedZone, error) {
	signedZone := &SignedZone{
		Zone:   domainName,
		Ds:     &RRSet{},
		Dnskey: &RRSet{},
	}
	signedZone.PubKeyLookup = make(map[uint16]*dns.DNSKEY)

	var g errgroup.Group
	g.Go(func() error {
		var err error
		signedZone.Dnskey, err = getRRset(domainName, dns.TypeDNSKEY, resolver, ci)
		if err != nil {
			return err
		}

		for _, rr := range signedZone.Dnskey.RrSet {
			signedZone.addPubKey(rr.(*dns.DNSKEY))
		}
		return nil
	})

	g.Go(func() error {
		var err error
		signedZone.Ds, err = getRRset(domainName, dns.TypeDS, resolver, ci)
		if err != nil {
			return ErrDsFailed
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return signedZone, nil
}

func (authChain *AuthenticationChain) Populate(domainName string, resolver Resolver, ci ClientInfo) error {
	qnameComponents := strings.Split(domainName, ".")
	zonesToVerify := len(qnameComponents)
	authChain.DelegationChain = make([]SignedZone, zonesToVerify)

	var g errgroup.Group
	for i := 0; i < zonesToVerify; i++ {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[i:], "."))
		index := i

		g.Go(func() error {
			delegation, err := queryDelegation(zoneName, resolver, ci)
			if err != nil {
				return err
			}
			authChain.DelegationChain[index] = *delegation
			if index > 0 {
				authChain.DelegationChain[index-1].ParentZone = delegation
			}
			return nil
		})
	}

	return g.Wait()
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
		if signedZone.Dnskey.isEmpty() {
			return ErrDnskeyNotAvailable
		}

		err := signedZone.verifyRRSIG(signedZone.Dnskey)
		if err != nil {
			return ErrRrsigValidationError
		}

		if signedZone.ParentZone != nil {
			if signedZone.Ds.isEmpty() {
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
	if !signedRRset.isSigned() {
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
