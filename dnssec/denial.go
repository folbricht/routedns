package dnssec

import (
	"errors"
	"fmt"
	"slices"

	"github.com/miekg/dns"
)

// ErrBogusDenial is returned when an empty DS response lacks an
// authenticated NSEC/NSEC3 proof that the DS RRset does not exist.
// Callers must treat this as a validation failure (bogus), never as an
// insecure delegation.
var ErrBogusDenial = errors.New("dnssec: unauthenticated denial of DS")

// verifyDSDenial checks that resp's authority section carries NSEC or NSEC3
// records, signed by one of the supplied parent-zone keys, that prove no DS
// RRset exists at name. RFC 4035 §5.2 / RFC 5155 §8.
func verifyDSDenial(resp *dns.Msg, name string, parentKeys []*dns.DNSKEY) error {
	name = dns.CanonicalName(name)
	rrsets, sigs := groupRRsByTypeAndName(resp.Ns)

	for key, rrset := range rrsets {
		if key.rrtype != dns.TypeNSEC && key.rrtype != dns.TypeNSEC3 {
			continue
		}
		sig, ok := sigs[key]
		if !ok {
			continue
		}
		if err := verifyRRSIG(sig, parentKeys, rrset); err != nil {
			continue
		}
		for _, rr := range rrset {
			switch r := rr.(type) {
			case *dns.NSEC:
				if nsecDeniesDS(r, name) {
					return nil
				}
			case *dns.NSEC3:
				if nsec3DeniesDS(r, name) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%w for %s", ErrBogusDenial, name)
}

// nsecDeniesDS reports whether the NSEC record proves an insecure delegation
// at name: the name exists as a delegation (NS bit set) in the parent zone
// but carries no DS. RFC 6840 §4.4.
func nsecDeniesDS(r *dns.NSEC, name string) bool {
	if dns.CanonicalName(r.Hdr.Name) != name {
		return false
	}
	return bitmapProvesInsecureDelegation(r.TypeBitMap)
}

// nsec3DeniesDS reports whether the NSEC3 record proves an insecure
// delegation at name, either by an exact hash match with NS-but-no-DS, or by
// an opt-out span covering the hashed name (RFC 5155 §6, §8.6).
func nsec3DeniesDS(r *dns.NSEC3, name string) bool {
	if r.Match(name) {
		return bitmapProvesInsecureDelegation(r.TypeBitMap)
	}
	return r.Flags&1 != 0 && r.Cover(name)
}

// bitmapProvesInsecureDelegation reports whether an NSEC/NSEC3 type bitmap at
// a delegation point indicates an unsigned child: NS present, DS and SOA
// absent. SOA present would mean we are at the child apex, not the parent
// side of the cut.
func bitmapProvesInsecureDelegation(bitmap []uint16) bool {
	return slices.Contains(bitmap, dns.TypeNS) &&
		!slices.Contains(bitmap, dns.TypeDS) &&
		!slices.Contains(bitmap, dns.TypeSOA)
}
