package dnssec

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoSignature        = errors.New("dnssec: no RRSIG for RRset")
	ErrNoKey              = errors.New("dnssec: no matching DNSKEY")
	ErrSignatureInvalid   = errors.New("dnssec: signature verification failed")
	ErrDSMismatch         = errors.New("dnssec: DNSKEY doesn't match DS")
	ErrNoTrustAnchor        = errors.New("dnssec: no trust anchor")
	ErrInsecureDelegation   = errors.New("dnssec: insecure delegation")
	ErrSignerOutOfBailiwick = errors.New("dnssec: RRSIG signer name out of bailiwick")
)

type Validator struct {
	ks *keystore

	now      func() time.Time
	resolver func(q *dns.Msg) (*dns.Msg, error)
}

type ValidatorOption func(*Validator)

// WithTime allows tests to set the current time. Defaults to time.Now
func WithTime(f func() time.Time) ValidatorOption {
	return func(v *Validator) {
		v.now = f
	}
}

// WithResolver sets a function the validator uses to resolve DNSSEC records
// as needed. It is strongly recommended to set this. Defaults to using
// plain UDP with Cloudflare DNS.
func WithResolver(f func(q *dns.Msg) (*dns.Msg, error)) ValidatorOption {
	return func(v *Validator) {
		v.resolver = f
	}
}

func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		now: time.Now,
		resolver: func(q *dns.Msg) (*dns.Msg, error) {
			return dns.Exchange(q, "1.1.1.1:53")
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	v.ks = newKeystore(v.now)
	return v
}

// SetAnchor adds a trust anchor to the validator. Typically the owner would be "." for the root key,
// but other anchors on sub-domains can be set as well. Inserts a permanent (max TTL) DS record for
// the given owner.
func (v *Validator) SetAnchor(owner string, tag uint16, alg, digestType uint8, digest string) {
	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   dns.CanonicalName(owner),
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    math.MaxUint32,
		},
		KeyTag:     tag,
		Algorithm:  alg,
		DigestType: digestType,
		Digest:     strings.ToUpper(digest),
	}
	v.ks.addDS(owner, ds)
}

// Validate checks the DNSSEC signatures in a DNS response message.
// It groups the answer section into RRsets, finds covering RRSIGs,
// and validates each signed RRset against a chain of trust.
func (v *Validator) Validate(answer *dns.Msg) error {
	if len(answer.Answer) == 0 {
		return nil
	}

	rrsets, sigs := groupRRsByTypeAndName(answer.Answer)

	for key, rrset := range rrsets {
		sig, ok := sigs[key]
		if !ok {
			// Check if this is an insecure delegation by looking for DS in parent
			zone := rrset[0].Header().Name
			if err := v.checkInsecureDelegation(zone); err != nil {
				return err
			}
			return fmt.Errorf("%w: %s/%s", ErrNoSignature, key.name, dns.TypeToString[key.rrtype])
		}
		if err := v.validateRRset(rrset, sig); err != nil {
			return err
		}
	}
	return nil
}

// checkInsecureDelegation walks the delegation chain from the root toward
// name, returning ErrInsecureDelegation at the first cut where the parent
// authentically proves (via signed NSEC/NSEC3) that no DS record exists.
// An empty DS response without such proof is bogus, not insecure
// (RFC 4035 §5.2, RFC 6840 §5.2).
func (v *Validator) checkInsecureDelegation(name string) error {
	name = dns.CanonicalName(name)
	if name == "." {
		return nil
	}
	labels := dns.SplitDomainName(name)
	for i := len(labels) - 1; i >= 0; i-- {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		insecure, err := v.proveNoDS(zone)
		if err != nil {
			return err
		}
		if insecure {
			return fmt.Errorf("%w: %s", ErrInsecureDelegation, zone)
		}
	}
	return nil
}

// proveNoDS returns true when zone has no DS RRset and that absence is
// authenticated by the parent zone's signed NSEC/NSEC3. It returns false when
// DS records are present, and an error when the absence cannot be
// authenticated.
func (v *Validator) proveNoDS(zone string) (bool, error) {
	ds, _, resp, err := v.lookupDS(zone)
	if err != nil {
		return false, err
	}
	if len(ds) > 0 {
		return false, nil
	}
	parent := parentZone(zone)
	parentZSK, _, err := v.buildChainOfTrust(parent)
	if err != nil {
		if errors.Is(err, ErrInsecureDelegation) {
			return true, nil
		}
		return false, err
	}
	if err := verifyDSDenial(resp, zone, parentZSK); err != nil {
		return false, err
	}
	return true, nil
}

// validateRRset validates a set of RRs against the provided RRSIG by
// building a chain of trust to the signer's DNSKEY.
func (v *Validator) validateRRset(rrset []dns.RR, sig *dns.RRSIG) error {
	// RFC 4035 §5.3.1: the RRSIG Signer's Name MUST be the zone that
	// contains the RRset, i.e. equal to or an ancestor of the owner name.
	// miekg/dns Verify() only does a textual strings.HasSuffix check, so a
	// signer "tim." would be accepted for owner "victim." — enforce a
	// label-aware comparison here before fetching keys for the signer.
	owner := dns.CanonicalName(rrset[0].Header().Name)
	signer := dns.CanonicalName(sig.SignerName)
	// dns.IsSubDomain(parent, child): true when child is at or below parent.
	if !dns.IsSubDomain(signer, owner) {
		return fmt.Errorf("%w: %s cannot sign %s", ErrSignerOutOfBailiwick, signer, owner)
	}
	zsk, _, err := v.buildChainOfTrust(signer)
	if err != nil {
		return err
	}
	return verifyRRSIG(sig, zsk, rrset)
}

// buildChainOfTrust recursively builds a DNSSEC chain of trust from
// the root trust anchor down to the specified zone. It returns the
// validated ZSK and KSK for the zone.
func (v *Validator) buildChainOfTrust(zone string) (zsk, ksk []*dns.DNSKEY, err error) {
	zone = dns.CanonicalName(zone)

	// Check cache first
	if zsk, ksk := v.ks.getDNSKEY(zone); zsk != nil || ksk != nil {
		return zsk, ksk, nil
	}

	// Fetch DNSKEY records for this zone
	fetchedZSK, fetchedKSK, dnsSigs, err := v.lookupDNSKEY(zone)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup DNSKEY for %s: %w", zone, err)
	}
	if len(fetchedKSK) == 0 {
		return nil, nil, fmt.Errorf("%w: no KSK for %s", ErrNoKey, zone)
	}

	allKeys := make([]dns.RR, 0, len(fetchedZSK)+len(fetchedKSK))
	for _, k := range fetchedZSK {
		allKeys = append(allKeys, k)
	}
	for _, k := range fetchedKSK {
		allKeys = append(allKeys, k)
	}

	// Obtain authenticated DS records for this zone — from the configured
	// trust anchor for the root, or by recursing into the parent otherwise.
	var dsRecords []*dns.DS
	if zone == "." {
		dsRecords = v.ks.getDS(".")
		if len(dsRecords) == 0 {
			return nil, nil, ErrNoTrustAnchor
		}
	} else {
		var (
			dsSigs []*dns.RRSIG
			dsResp *dns.Msg
		)
		dsRecords, dsSigs, dsResp, err = v.lookupDS(zone)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to lookup DS for %s: %w", zone, err)
		}

		parent := parentZone(zone)
		parentZSK, _, err := v.buildChainOfTrust(parent)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build chain of trust for parent %s: %w", parent, err)
		}

		if len(dsRecords) == 0 {
			if err := verifyDSDenial(dsResp, zone, parentZSK); err != nil {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("%w: %s", ErrInsecureDelegation, zone)
		}
		if len(dsSigs) == 0 {
			return nil, nil, fmt.Errorf("%w: DS for %s", ErrNoSignature, zone)
		}

		dsRRset := make([]dns.RR, len(dsRecords))
		for i, d := range dsRecords {
			dsRRset[i] = d
		}
		var verified bool
		for _, dsSig := range dsSigs {
			if err := verifyRRSIG(dsSig, parentZSK, dsRRset); err == nil {
				verified = true
				break
			}
		}
		if !verified {
			return nil, nil, fmt.Errorf("%w: DS RRSIG for %s", ErrSignatureInvalid, zone)
		}
	}

	// RFC 4035 §5.2: the DNSKEY RRset must be signed by a key that itself
	// chains to an authenticated DS. Restrict candidate signing keys to
	// those matching a DS before accepting the self-signature.
	trustedKSK := filterKeysByDS(fetchedKSK, dsRecords)
	if len(trustedKSK) == 0 {
		return nil, nil, fmt.Errorf("KSK doesn't match DS for %s: %w", zone, ErrDSMismatch)
	}

	var sigSeen, sigVerified bool
	for _, sig := range dnsSigs {
		if dns.CanonicalName(sig.SignerName) != zone || sig.TypeCovered != dns.TypeDNSKEY {
			continue
		}
		sigSeen = true
		if err := verifyRRSIG(sig, trustedKSK, allKeys); err == nil {
			sigVerified = true
			break
		}
	}
	if !sigSeen {
		return nil, nil, fmt.Errorf("%w: no RRSIG covering DNSKEY for %s", ErrNoSignature, zone)
	}
	if !sigVerified {
		return nil, nil, fmt.Errorf("DNSKEY self-signature verification failed for %s: %w", zone, ErrSignatureInvalid)
	}

	// Cache the validated keys
	allDNSKEYs := slices.Concat(fetchedZSK, fetchedKSK)
	v.ks.addDNSKEY(zone, allDNSKEYs)

	return fetchedZSK, fetchedKSK, nil
}

// lookupDNSKEY queries for DNSKEY records for the given zone and returns
// the ZSKs, KSKs, and RRSIGs from the response.
func (v *Validator) lookupDNSKEY(name string) (zsk, ksk []*dns.DNSKEY, sigs []*dns.RRSIG, err error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.CanonicalName(name), dns.TypeDNSKEY)
	q.SetEdns0(4096, true)
	q.MsgHdr.CheckingDisabled = true
	a, err := v.resolver(q)
	if err != nil {
		return nil, nil, nil, err
	}
	if a.Rcode != dns.RcodeSuccess {
		return nil, nil, nil, fmt.Errorf("DNSKEY lookup for %q failed: rcode %s", name, dns.RcodeToString[a.Rcode])
	}
	for _, rr := range a.Answer {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			switch r.Flags {
			case 257:
				ksk = append(ksk, r)
			case 256:
				zsk = append(zsk, r)
			}
		case *dns.RRSIG:
			sigs = append(sigs, r)
		}
	}
	return
}

// lookupDS queries for DS records for the given zone and returns the DS
// records, their covering RRSIGs, and the full response so callers can
// inspect the authority section for NSEC/NSEC3 denial.
func (v *Validator) lookupDS(name string) ([]*dns.DS, []*dns.RRSIG, *dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.CanonicalName(name), dns.TypeDS)
	q.SetEdns0(4096, true)
	q.MsgHdr.CheckingDisabled = true
	a, err := v.resolver(q)
	if err != nil {
		return nil, nil, nil, err
	}
	var (
		ds   []*dns.DS
		sigs []*dns.RRSIG
	)
	if a.Rcode == dns.RcodeSuccess {
		for _, rr := range a.Answer {
			switch r := rr.(type) {
			case *dns.DS:
				ds = append(ds, r)
			case *dns.RRSIG:
				if r.TypeCovered == dns.TypeDS {
					sigs = append(sigs, r)
				}
			}
		}
	}
	return ds, sigs, a, nil
}

// parentZone returns the parent zone of the given zone name.
// "example.com." → "com.", "com." → "."
func parentZone(name string) string {
	name = dns.CanonicalName(name)
	if name == "." {
		return "."
	}
	_, parent, found := strings.Cut(name, ".")
	if !found || parent == "" {
		return "."
	}
	return parent
}

// findKeysByTag returns DNSKEY records matching the given key tag and algorithm.
func findKeysByTag(keys []*dns.DNSKEY, tag uint16, alg uint8) []*dns.DNSKEY {
	var result []*dns.DNSKEY
	for _, key := range keys {
		if key.KeyTag() == tag && key.Algorithm == alg {
			result = append(result, key)
		}
	}
	return result
}

// verifyRRSIG attempts to verify an RRSIG against a set of keys and an RRset.
// It returns nil on the first successful verification.
func verifyRRSIG(sig *dns.RRSIG, keys []*dns.DNSKEY, rrset []dns.RR) error {
	matching := findKeysByTag(keys, sig.KeyTag, sig.Algorithm)
	if len(matching) == 0 {
		return fmt.Errorf("%w: tag=%d alg=%d", ErrNoKey, sig.KeyTag, sig.Algorithm)
	}
	var lastErr error
	for _, key := range matching {
		if err := sig.Verify(key, rrset); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("%w: %v", ErrSignatureInvalid, lastErr)
}

// filterKeysByDS returns the subset of keys whose computed DS digest matches
// one of the provided DS records.
func filterKeysByDS(keys []*dns.DNSKEY, ds []*dns.DS) []*dns.DNSKEY {
	var result []*dns.DNSKEY
	for _, key := range keys {
		for _, d := range ds {
			computed := key.ToDS(d.DigestType)
			if computed == nil {
				continue
			}
			if strings.EqualFold(computed.Digest, d.Digest) {
				result = append(result, key)
				break
			}
		}
	}
	return result
}

// rrsetKey identifies an RRset by name and type.
type rrsetKey struct {
	name   string
	rrtype uint16
}

// groupRRsByTypeAndName groups the RRs in a section into RRsets keyed by
// (canonical name, type) and extracts covering RRSIGs.
func groupRRsByTypeAndName(section []dns.RR) (map[rrsetKey][]dns.RR, map[rrsetKey]*dns.RRSIG) {
	rrsets := make(map[rrsetKey][]dns.RR)
	sigs := make(map[rrsetKey]*dns.RRSIG)

	for _, rr := range section {
		if sig, ok := rr.(*dns.RRSIG); ok {
			key := rrsetKey{
				name:   dns.CanonicalName(sig.Hdr.Name),
				rrtype: sig.TypeCovered,
			}
			// Keep the first RRSIG for each RRset (could be enhanced to try multiple)
			if _, exists := sigs[key]; !exists {
				sigs[key] = sig
			}
			continue
		}
		hdr := rr.Header()
		key := rrsetKey{
			name:   dns.CanonicalName(hdr.Name),
			rrtype: hdr.Rrtype,
		}
		rrsets[key] = append(rrsets[key], rr)
	}

	return rrsets, sigs
}
