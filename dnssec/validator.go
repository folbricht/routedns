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
	ErrNoTrustAnchor      = errors.New("dnssec: no trust anchor")
	ErrInsecureDelegation = errors.New("dnssec: insecure delegation")
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

// checkInsecureDelegation checks whether a zone is an insecure delegation
// (i.e., the parent zone has no DS record for it).
func (v *Validator) checkInsecureDelegation(zone string) error {
	if zone == "." {
		return nil
	}
	ds, _, err := v.lookupDS(zone)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		return fmt.Errorf("%w: %s", ErrInsecureDelegation, zone)
	}
	return nil
}

// validateRRset validates a set of RRs against the provided RRSIG by
// building a chain of trust to the signer's DNSKEY.
func (v *Validator) validateRRset(rrset []dns.RR, sig *dns.RRSIG) error {
	zsk, _, err := v.buildChainOfTrust(sig.SignerName)
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

	// Find an RRSIG covering the DNSKEY RRset signed by this zone
	allKeys := make([]dns.RR, 0, len(fetchedZSK)+len(fetchedKSK))
	for _, k := range fetchedZSK {
		allKeys = append(allKeys, k)
	}
	for _, k := range fetchedKSK {
		allKeys = append(allKeys, k)
	}

	var dnsSig *dns.RRSIG
	for _, sig := range dnsSigs {
		if dns.CanonicalName(sig.SignerName) == zone && sig.TypeCovered == dns.TypeDNSKEY {
			dnsSig = sig
			break
		}
	}
	if dnsSig == nil {
		return nil, nil, fmt.Errorf("%w: no RRSIG covering DNSKEY for %s", ErrNoSignature, zone)
	}

	// Verify the DNSKEY RRset self-signature using a KSK
	if err := verifyRRSIG(dnsSig, fetchedKSK, allKeys); err != nil {
		return nil, nil, fmt.Errorf("DNSKEY self-signature verification failed for %s: %w", zone, err)
	}

	if zone == "." {
		// For the root zone, validate KSK against the trust anchor DS records
		ds := v.ks.getDS(".")
		if len(ds) == 0 {
			return nil, nil, ErrNoTrustAnchor
		}
		if err := verifyDNSKEYWithDS(fetchedKSK, ds); err != nil {
			return nil, nil, fmt.Errorf("root KSK doesn't match trust anchor: %w", err)
		}
	} else {
		// For non-root zones, look up DS from parent and validate
		dsRecords, dsSigs, err := v.lookupDS(zone)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to lookup DS for %s: %w", zone, err)
		}
		if len(dsRecords) == 0 {
			return nil, nil, fmt.Errorf("%w: %s", ErrInsecureDelegation, zone)
		}

		// Recursively build chain of trust for the parent zone
		parent := parentZone(zone)
		parentZSK, _, err := v.buildChainOfTrust(parent)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build chain of trust for parent %s: %w", parent, err)
		}

		// Verify the DS RRSIG with the parent's ZSK
		if len(dsSigs) > 0 {
			dsRRset := make([]dns.RR, len(dsRecords))
			for i, d := range dsRecords {
				dsRRset[i] = d
			}
			// Try each DS RRSIG
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

		// Verify that a KSK matches a DS record
		if err := verifyDNSKEYWithDS(fetchedKSK, dsRecords); err != nil {
			return nil, nil, fmt.Errorf("KSK doesn't match DS for %s: %w", zone, err)
		}
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

// lookupDS queries for DS records for the given zone and returns
// the DS records and their covering RRSIGs.
func (v *Validator) lookupDS(name string) ([]*dns.DS, []*dns.RRSIG, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.CanonicalName(name), dns.TypeDS)
	q.SetEdns0(4096, true)
	q.MsgHdr.CheckingDisabled = true
	a, err := v.resolver(q)
	if err != nil {
		return nil, nil, err
	}
	if a.Rcode != dns.RcodeSuccess {
		// NXDOMAIN or other errors mean no DS — insecure delegation
		return nil, nil, nil
	}
	var (
		ds   []*dns.DS
		sigs []*dns.RRSIG
	)
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
	return ds, sigs, nil
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

// verifyDNSKEYWithDS verifies that at least one of the provided KSKs
// matches one of the DS records by computing the DS digest from the key
// and comparing it.
func verifyDNSKEYWithDS(ksk []*dns.DNSKEY, ds []*dns.DS) error {
	for _, d := range ds {
		for _, key := range ksk {
			computed := key.ToDS(d.DigestType)
			if computed == nil {
				continue
			}
			if strings.EqualFold(computed.Digest, d.Digest) {
				return nil
			}
		}
	}
	return ErrDSMismatch
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
