package rdns

import (
	"cmp"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

var (
	ErrResourceNotSigned  = errors.New("resource is not signed with RRSIG")
	ErrNoResult           = errors.New("requested RR not found")
	ErrDnskeyNotAvailable = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable     = errors.New("DS RR does not exist")
	ErrInvalidRRsig       = errors.New("invalid RRSIG")
)

type RRSet struct {
	RrSet []dns.RR
	RrSig *dns.RRSIG
}

func (r *RRSet) isSigned() bool {
	return r.RrSig != nil
}

func (r *RRSet) isEmpty() bool {
	return len(r.RrSet) < 1
}

type SignedZone struct {
	Zone         string
	Dnskey       *RRSet
	Ds           *RRSet
	ParentZone   *SignedZone
	PubKeyLookup map[uint16]*dns.DNSKEY
}

func (z SignedZone) lookupPubKey(keyTag uint16) *dns.DNSKEY {
	return z.PubKeyLookup[keyTag]
}

func (z SignedZone) addPubKey(k *dns.DNSKEY) {
	z.PubKeyLookup[k.KeyTag()] = k
}

type AuthenticationChain struct {
	DelegationChain []SignedZone
}

func forwardResponse(response *dns.Msg, doIsSet bool) *dns.Msg {
	if !doIsSet {
		var filteredAnswers []dns.RR
		filteredResponse := response.Copy()
		for _, rr := range filteredResponse.Answer {
			if _, isRRSIG := rr.(*dns.RRSIG); !isRRSIG {
				filteredAnswers = append(filteredAnswers, rr)
			}
		}

		filteredResponse.Ns = nil
		filteredResponse.Answer = filteredAnswers
		return filteredResponse
	}
	return response
}

func setDNSSECdo(q *dns.Msg) *dns.Msg {
	if q.IsEdns0() == nil {
		q.SetEdns0(1024, true)
	}
	q.IsEdns0().SetDo()
	return q
}

func getRRset(qname string, qtype uint16, resolver Resolver, ci ClientInfo) (*RRSet, error) {
	q := &dns.Msg{}
	q.SetEdns0(4096, true)
	q.SetQuestion(qname, qtype)

	r, err := resolver.Resolve(q, ci)
	if err != nil || r == nil {
		return nil, ErrNoResult
	}
	if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
		return extractRRset(r, qtype), nil
	}
	return nil, ErrInvalidRRsig
}

func extractRRset(r *dns.Msg, qtype uint16) *RRSet {
	result := &RRSet{RrSet: []dns.RR{}}
	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			if t.TypeCovered == qtype {
				result.RrSig = t
			}
		default:
			if rr.Header().Rrtype == qtype {
				result.RrSet = append(result.RrSet, rr)
			}
		}
	}
	return result
}

func extractNSEC(r *dns.Msg) ([]dns.RR, error) {
	result := []dns.RR{}
	isNSEC := false
	isNSEC3 := false

	for _, rr := range r.Ns {
		rrType := rr.Header().Rrtype
		switch rrType {
		case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG:
			result = append(result, rr)

			switch rrType {
			case dns.TypeNSEC:
				isNSEC = true
			case dns.TypeNSEC3:
				isNSEC3 = true
			}
		}
	}

	if isNSEC && isNSEC3 {
		return nil, errors.New("bogus mixed NSEC records")
	}
	return result, nil
}

func queryDelegation(domainName string, resolver Resolver, ci ClientInfo) (*SignedZone, error) {
	signedZone := &SignedZone{
		Zone:         domainName,
		PubKeyLookup: make(map[uint16]*dns.DNSKEY),
	}

	var g errgroup.Group
	g.Go(func() error {
		var err error
		signedZone.Dnskey, err = getRRset(domainName, dns.TypeDNSKEY, resolver, ci)
		if err != nil {
			return err
		}

		if signedZone.Dnskey.isEmpty() {
			return ErrDnskeyNotAvailable
		}

		for _, rr := range signedZone.Dnskey.RrSet {
			signedZone.addPubKey(rr.(*dns.DNSKEY))
		}
		return nil
	})

	g.Go(func() error {
		if domainName == "." {
			return nil
		}
		var err error
		signedZone.Ds, err = getRRset(domainName, dns.TypeDS, resolver, ci)
		if err != nil {
			return err
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
	for zone := range zonesToVerify {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[zone:], "."))
		g.Go(func() error {
			delegation, err := queryDelegation(zoneName, resolver, ci)
			if err != nil {
				return err
			}
			authChain.DelegationChain[zone] = *delegation
			if zone > 0 {
				authChain.DelegationChain[zone-1].ParentZone = delegation
			}
			return nil
		})
	}

	return g.Wait()
}

func (authChain *AuthenticationChain) Verify(answerRRset *RRSet, rootKeys *RRSet) error {
	zones := authChain.DelegationChain
	if len(zones) == 0 {
		return errors.New("AuthChain has no Delegations")
	}

	signedZone := authChain.DelegationChain[0]
	if signedZone.Dnskey.isEmpty() {
		return ErrDnskeyNotAvailable
	}

	err := signedZone.verifyRRSIG(answerRRset)
	if err != nil {
		return ErrInvalidRRsig
	}

	for _, signedZone := range authChain.DelegationChain {
		if signedZone.Zone == "." && rootKeys != nil {
			if err := validateRootDNSKEY(signedZone.Dnskey, rootKeys); err != nil {
				return err
			}
		}
		if signedZone.Dnskey.isEmpty() {
			return ErrDnskeyNotAvailable
		}

		err := signedZone.verifyRRSIG(signedZone.Dnskey)
		if err != nil {
			return errors.New("RR doesn't validate against RRSIG")
		}

		if signedZone.ParentZone != nil {
			if signedZone.Ds.isEmpty() {
				return ErrDsNotAvailable
			}

			err := signedZone.ParentZone.verifyRRSIG(signedZone.Ds)
			if err != nil {
				return errors.New("RR doesn't validate against RRSIG")
			}
			err = signedZone.verifyDS(signedZone.Ds.RrSet)
			if err != nil {
				return errors.New("DS RR does not match DNSKEY")
			}
		}
	}
	return nil
}

func (authChain *AuthenticationChain) ValidateNSEC(nsec []dns.RR) ([]dns.RR, error) {
	if len(nsec) == 0 {
		return nil, errors.New("no NSEC or NSEC3 records found")
	}

	var validNsecSet []dns.RR
	for _, rr := range nsec {
		if rr.Header().Rrtype != dns.TypeRRSIG {
			continue
		}
		rrsig := rr.(*dns.RRSIG)
		if !rrsig.ValidityPeriod(time.Now().UTC()) {
			Log.Debug("expired RRSIG")
			continue
		}

		var key *dns.DNSKEY
		for _, signedZone := range authChain.DelegationChain {
			key = signedZone.lookupPubKey(rrsig.KeyTag)
			if key != nil {
				break
			}
		}

		if key == nil {
			Log.Debug("no matching DNSKEY found for RRSIG")
			continue
		}

		myset := findNSEC(nsec, rr.Header().Name, rrsig.TypeCovered)
		if myset != nil {
			if err := rrsig.Verify(key, myset); err == nil {
				validNsecSet = append(validNsecSet, myset...)
				Log.Debug("successfully validated", slog.String("qtype", dns.TypeToString[rrsig.TypeCovered]))
			} else {
				Log.Debug("NSEC validation failed", slog.String("error", err.Error()))
			}
		}
	}

	if len(validNsecSet) == 0 {
		return nil, errors.New("no valid NSEC or NSEC3 records found")
	}
	return validNsecSet, nil
}

func findNSEC(l []dns.RR, name string, t uint16) []dns.RR {
	var l1 []dns.RR
	for _, rr := range l {
		if strings.EqualFold(rr.Header().Name, name) && rr.Header().Rrtype == t {
			l1 = append(l1, rr)
		}
	}
	return l1
}

func (z SignedZone) verifyRRSIG(signedRRset *RRSet) error {
	if !signedRRset.isSigned() {
		return errors.New("RRSIG does not exist")
	}

	key := z.lookupPubKey(signedRRset.RrSig.KeyTag)
	if key == nil {
		return ErrDnskeyNotAvailable
	}

	err := signedRRset.RrSig.Verify(key, signedRRset.RrSet)
	if err != nil {
		return err
	}

	if !signedRRset.RrSig.ValidityPeriod(time.Now()) {
		return errors.New("invalid RRSIG validity period")
	}
	return nil
}

func (z SignedZone) verifyDS(dsRrset []dns.RR) error {
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
		return errors.New("DS RR does not match DNSKEY")
	}
	return errors.New("unknown DS digest type")
}

func validateRootDNSKEY(dnskeyRRset *RRSet, rootKeys *RRSet) error {
	if dnskeyRRset == nil || dnskeyRRset.RrSet == nil || dnskeyRRset.RrSig == nil {
		return errors.New("missing DNSKEY or RRSIG for root")
	}

	for _, key := range rootKeys.RrSet {
		Log.Debug(key.String())
		if dnsKey, ok := key.(*dns.DNSKEY); ok {
			err := dnskeyRRset.RrSig.Verify(dnsKey, dnskeyRRset.RrSet)
			if err == nil {
				return nil
			}
		}
	}
	return errors.New("root DNSKEY validation failed with all keys")
}

func denialNSEC(nsec []dns.RR, qname string, qtype uint16) error {
	var nameExistsNSEC *dns.NSEC
	var coveringNSEC *dns.NSEC

	for _, rr := range nsec {
		n, _ := rr.(*dns.NSEC)
		ownerName := strings.ToLower(dns.Fqdn(n.Header().Name))
		nextDomain := strings.ToLower(dns.Fqdn(n.NextDomain))

		ownerComparedToQname, err := canonicalNameCompare(ownerName, qname)
		if err != nil {
			return fmt.Errorf("internal error comparing ownerName '%s': %w", ownerName, err)
		}

		nextComparedToQname, err := canonicalNameCompare(nextDomain, qname)
		if err != nil {
			return fmt.Errorf("internal error comparing nextDomain '%s': %w", nextDomain, err)
		}

		ownerComparedToNext, err := canonicalNameCompare(ownerName, nextDomain)
		if err != nil {
			return fmt.Errorf("internal error comparing NSEC owner '%s' vs next '%s': %w", ownerName, nextDomain, err)
		}

		if ownerComparedToQname == 0 {
			nameExistsNSEC = n
			continue
		}

		isCovering := false
		if ownerComparedToQname == -1 && nextComparedToQname == 1 {
			isCovering = true
		} else {
			if ownerComparedToNext == 1 {
				if ownerComparedToQname == -1 || nextComparedToQname == 1 {
					isCovering = true
				}
			}
		}

		if isCovering {
			coveringNSEC = n
			continue
		}
	}

	if coveringNSEC != nil {
		if nameExistsNSEC != nil {
			return errors.New("NSEC denial failed: contradictory NSEC records received (NXDOMAIN proof and NODATA proof)")
		}
		return nil
	}

	if nameExistsNSEC != nil {
		if slices.Contains(nameExistsNSEC.TypeBitMap, qtype) {
			return fmt.Errorf("NSEC denial failed: type %s proven to exist for %s via NSEC bitmap", dns.TypeToString[qtype], qname)
		}
		Log.Debug("NSEC proven non-existence")
		return nil
	}
	return errors.New("NSEC denial failed: no validated NSEC record found proving non-existence for the query")
}

func denialNSEC3(nsec3 []dns.RR, qname string, qtype uint16, rcodeStr string) error {
	var firstParams *dns.NSEC3
	if n3, ok := nsec3[0].(*dns.NSEC3); ok {
		firstParams = n3
	} else {
		foundFirst := false
		for _, rr := range nsec3 {
			if n3, ok := rr.(*dns.NSEC3); ok {
				firstParams = n3
				foundFirst = true
				break
			}
		}
		if !foundFirst {
			return errors.New("NSEC3 denial check: no NSEC3 records found in input slice")
		}
	}

	for _, rr := range nsec3 {
		n3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}

		if n3.Hash != firstParams.Hash ||
			n3.Flags != firstParams.Flags ||
			n3.Iterations != firstParams.Iterations ||
			n3.Salt != firstParams.Salt {
			return errors.New("NSEC3 denial failed: inconsistent parameters in provided records")
		}
	}

	switch rcodeStr {
	case dns.RcodeToString[dns.RcodeSuccess]:
		var matchingNSEC3 *dns.NSEC3
		matchCount := 0

		for _, rr := range nsec3 {
			n3, ok := rr.(*dns.NSEC3)
			if !ok {
				continue
			}

			if n3.Match(qname) {
				matchingNSEC3 = n3
				matchCount++
			}
		}

		if matchCount == 0 {
			return errors.New("NSEC3 denial failed (NODATA): no NSEC3 record matches qname hash")
		}
		if matchCount > 1 {
			return errors.New("NSEC3 denial failed (NODATA): multiple NSEC3 records match qname hash")
		}
		if slices.Contains(matchingNSEC3.TypeBitMap, qtype) {
			return fmt.Errorf("NSEC3 denial failed: type %s proven to exist for %s via NSEC3 bitmap", dns.TypeToString[qtype], qname)
		}
		return nil

	case dns.RcodeToString[dns.RcodeNameError]:
		qLabels := dns.SplitDomainName(qname)
		if qLabels == nil {
			if qname == "." {
				return errors.New("NSEC3 denial failed (NXDOMAIN): cannot process root query for NXDOMAIN proof")
			}
			return errors.New("NSEC3 denial failed (NXDOMAIN): could not split qname into labels")
		}
		qLabelCount := dns.CountLabel(qname)

		var ce string = "."
	SearchCE:
		for i := range qLabelCount {
			ancestorLabels := qLabels[i:]
			potentialCE := dns.Fqdn(strings.Join(ancestorLabels, "."))

			for _, rr := range nsec3 {
				n3, ok := rr.(*dns.NSEC3)
				if !ok {
					continue
				}
				if n3.Match(potentialCE) {
					ce = potentialCE
					break SearchCE
				}
			}
		}

		var nc, wc string
		if ce == "." {
			if qLabelCount > 0 {
				nc = dns.Fqdn(qLabels[0])
			} else {
				return errors.New("NSEC3 denial failed (NXDOMAIN): qname is empty or root, cannot determine nc")
			}
			wc = "*."
		} else {
			ceLabelCount := dns.CountLabel(ce)
			if qLabelCount <= ceLabelCount {
				if qname == ce {
					return errors.New("NSEC3 denial failed (NXDOMAIN): qname matches closest encloser, but RCODE is NXDOMAIN")
				}
				return errors.New("NSEC3 denial failed (NXDOMAIN): inconsistent label counts for qname/ce")
			}

			ncLabelIndex := qLabelCount - ceLabelCount - 1
			ncLabels := qLabels[ncLabelIndex:]
			nc = dns.Fqdn(strings.Join(ncLabels, "."))
			wc = dns.Fqdn("*." + ce)
		}
		foundCeMatch := false
		foundNcCover := false
		foundWcCover := false

		for _, rr := range nsec3 {
			n3, ok := rr.(*dns.NSEC3)
			if !ok {
				continue
			}

			if n3.Match(ce) {
				foundCeMatch = true
			}
			if nc != "" && n3.Cover(nc) {
				foundNcCover = true
			}
			if wc != "" && n3.Cover(wc) {
				foundWcCover = true
			}
		}

		if foundCeMatch && foundNcCover && foundWcCover {
			Log.Debug("NSEC3 proven non-existence")
			return nil // Successful NXDOMAIN denial proof
		} else {
			return fmt.Errorf("NSEC3 denial failed (NXDOMAIN): proof incomplete")
		}
	default:
		return fmt.Errorf("NSEC3 denial check cannot prove denial for RCODE: %s", rcodeStr)
	}
}

// canonicalNameCompare optimizes DNS name comparison according to RFC 4034.
func canonicalNameCompare(name1 string, name2 string) (int, error) {
	if _, ok := dns.IsDomainName(dns.Fqdn(name1)); !ok {
		return 0, errors.New("invalid domain name")
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(name2)); !ok {
		return 0, errors.New("invalid domain name")
	}

	labels1 := dns.SplitDomainName(dns.Fqdn(name1))
	labels2 := dns.SplitDomainName(dns.Fqdn(name2))

	len1 := len(labels1)
	len2 := len(labels2)
	minLen := min(len1, len2)

	for i := 1; i <= minLen; i++ {
		label1 := labels1[len1-i]
		label2 := labels2[len2-i]
		res := strings.Compare(strings.ToLower(label1), strings.ToLower(label2))
		if res != 0 {
			return res, nil
		}
	}

	return cmp.Compare(len1, len2), nil
}

type TrustAnchor struct {
	Zone      string      `xml:"Zone"`
	KeyDigest []KeyDigest `xml:"KeyDigest"`
}

type KeyDigest struct {
	KeyTag     int    `xml:"KeyTag"`
	Algorithm  int    `xml:"Algorithm"`
	DigestType int    `xml:"DigestType"`
	Digest     string `xml:"Digest"`
	PublicKey  string `xml:"PublicKey"` // Base64 encoded DNSKEY
	Flags      int    `xml:"Flags"`
}

func loadRootKeysFromXML(filename string) (*RRSet, error) {
	xmlFile, err := os.ReadFile(filename)
	if err != nil {
		Log.Error("Error reading XML file", slog.String("error", err.Error()), slog.String("filename", filename))
		return nil, err
	}

	var trustAnchor TrustAnchor
	err = xml.Unmarshal(xmlFile, &trustAnchor)
	if err != nil {
		Log.Error("Error unmarshalling XML", slog.String("error", err.Error()), slog.String("filename", filename))
		return nil, err
	}

	rrSet := &RRSet{
		RrSet: make([]dns.RR, 0, len(trustAnchor.KeyDigest)),
	}

	for _, kd := range trustAnchor.KeyDigest {
		if kd.PublicKey == "" {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %s %d %d %d %s",
			trustAnchor.Zone, dns.TypeToString[dns.TypeDNSKEY], kd.Flags, 3, kd.Algorithm, kd.PublicKey))
		if err != nil {
			Log.Error("Error parsing DNSKEY", slog.String("error", err.Error()), slog.String("publicKey", kd.PublicKey))
			continue
		}
		dnsKey, ok := rr.(*dns.DNSKEY)
		if !ok {
			Log.Error("Error: RR is not a DNSKEY", slog.String("publicKey", kd.PublicKey))
			continue
		}
		rrSet.RrSet = append(rrSet.RrSet, dnsKey)
	}
	return rrSet, nil
}
