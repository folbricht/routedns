package dnssec

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// validateDenial authenticates a negative response (NXDOMAIN or NODATA). It
// verifies that the authority section carries signed NSEC/NSEC3 records that
// chain to the trust anchor and that actually prove the absence of the queried
// name/type. It returns nil when the denial is proven, ErrInsecureDelegation
// when the queried name falls under a provably unsigned zone (so the unsigned
// answer may be passed through), and an error otherwise (bogus).
//
// Without this, an attacker could forge an NXDOMAIN/NODATA with an empty
// answer section to suppress a record (e.g. a DANE/CAA downgrade) and have it
// accepted as authentic.
func (v *Validator) validateDenial(answer *dns.Msg) error {
	if len(answer.Question) == 0 {
		return fmt.Errorf("%w: response has no question", ErrDenialOfExistence)
	}
	q := answer.Question[0]
	qname := dns.CanonicalName(q.Name)
	qtype := q.Qtype

	nsecs, nsec3s := v.collectVerifiedDenialRecords(answer.Ns, qname)

	if nsecProvesDenial(nsecs, qname, qtype, answer.Rcode) {
		return nil
	}
	if nsec3ProvesDenial(nsec3s, qname, qtype, answer.Rcode) {
		return nil
	}

	// No authenticated proof of denial. Determine whether the name is in a
	// signed zone at all: if a parent provably has no DS this is an insecure
	// delegation and the unsigned negative answer may be passed through.
	// Otherwise the unproven denial is bogus.
	if err := v.checkInsecureDelegation(qname); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s/%s", ErrDenialOfExistence, qname, dns.TypeToString[qtype])
}

// collectVerifiedDenialRecords returns the NSEC and NSEC3 records from the
// authority section whose covering RRSIG is signed by a zone at or above qname
// and chains to the trust anchor. Unsigned or unauthenticated records are
// discarded so a forged proof cannot be used.
func (v *Validator) collectVerifiedDenialRecords(ns []dns.RR, qname string) (nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) {
	rrsets, sigs := groupRRsByTypeAndName(ns)
	for key, rrset := range rrsets {
		if key.rrtype != dns.TypeNSEC && key.rrtype != dns.TypeNSEC3 {
			continue
		}
		sig, ok := sigs[key]
		if !ok {
			continue
		}
		// The signer zone must be at or above the queried name; an NSEC/NSEC3
		// from an unrelated zone proves nothing about qname.
		signer := dns.CanonicalName(sig.SignerName)
		if !dns.IsSubDomain(signer, qname) {
			continue
		}
		zsk, _, err := v.buildChainOfTrust(signer)
		if err != nil {
			continue
		}
		if verifyRRSIG(sig, zsk, rrset, v.now()) != nil {
			continue
		}
		for _, rr := range rrset {
			switch r := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, r)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, r)
			}
		}
	}
	return nsecs, nsec3s
}

// nsecProvesDenial reports whether the authenticated NSEC records prove the
// denial for the given response code.
func nsecProvesDenial(nsecs []*dns.NSEC, qname string, qtype uint16, rcode int) bool {
	if len(nsecs) == 0 {
		return false
	}
	switch rcode {
	case dns.RcodeNameError:
		return nsecProvesNXDOMAIN(nsecs, qname)
	case dns.RcodeSuccess:
		return nsecProvesNODATA(nsecs, qname, qtype)
	}
	return false
}

// nsecProvesNODATA proves that qname exists but the queried type does not, via
// an NSEC matching qname whose bitmap lacks qtype, or via a wildcard NODATA.
func nsecProvesNODATA(nsecs []*dns.NSEC, qname string, qtype uint16) bool {
	qname = dns.CanonicalName(qname)

	// Direct NODATA: an NSEC owning qname with the type (and CNAME) absent.
	for _, n := range nsecs {
		if dns.CanonicalName(n.Hdr.Name) != qname {
			continue
		}
		return !slices.Contains(n.TypeBitMap, qtype) && !slices.Contains(n.TypeBitMap, dns.TypeCNAME)
	}

	// Wildcard NODATA: qname has no exact match (an NSEC covers it) but the
	// wildcard at the closest encloser matches with the type absent.
	for _, cover := range nsecs {
		if !nsecCovers(cover, qname) {
			continue
		}
		wildcard := dns.CanonicalName("*." + nsecClosestEncloser(qname, cover))
		for _, w := range nsecs {
			if dns.CanonicalName(w.Hdr.Name) != wildcard {
				continue
			}
			return !slices.Contains(w.TypeBitMap, qtype) && !slices.Contains(w.TypeBitMap, dns.TypeCNAME)
		}
	}
	return false
}

// nsecProvesNXDOMAIN proves that qname does not exist: an NSEC must cover it,
// and an NSEC must cover the wildcard at the closest encloser (so no wildcard
// could have synthesized an answer). RFC 4035 §5.4.
func nsecProvesNXDOMAIN(nsecs []*dns.NSEC, qname string) bool {
	qname = dns.CanonicalName(qname)

	var ce string
	covered := false
	for _, n := range nsecs {
		if nsecCovers(n, qname) {
			ce = nsecClosestEncloser(qname, n)
			covered = true
			break
		}
	}
	if !covered {
		return false
	}

	wildcard := dns.CanonicalName("*." + ce)
	for _, n := range nsecs {
		// An exact wildcard match contradicts NXDOMAIN; only a covering NSEC
		// (proving the wildcard does not exist) completes the proof.
		if dns.CanonicalName(n.Hdr.Name) == wildcard {
			return false
		}
		if nsecCovers(n, wildcard) {
			return true
		}
	}
	return false
}

// nsecClosestEncloser returns the closest encloser of qname implied by a
// covering NSEC: the longest ancestor of qname known to exist (the longer of
// the suffixes shared with the NSEC's owner and next-domain names).
func nsecClosestEncloser(qname string, n *dns.NSEC) string {
	owner := dns.CanonicalName(n.Hdr.Name)
	next := dns.CanonicalName(n.NextDomain)
	labels := max(dns.CompareDomainName(qname, owner), dns.CompareDomainName(qname, next))
	return lastNLabels(qname, labels)
}

// nsecCovers reports whether the NSEC record spans qname in canonical order,
// i.e. owner < qname < next, accounting for the wrap-around at the zone apex
// where next <= owner. An exact owner match is not "covered".
func nsecCovers(n *dns.NSEC, qname string) bool {
	owner := dns.CanonicalName(n.Hdr.Name)
	next := dns.CanonicalName(n.NextDomain)
	qname = dns.CanonicalName(qname)
	if qname == owner {
		return false
	}
	if canonicalNameCmp(owner, next) < 0 {
		return canonicalNameCmp(owner, qname) < 0 && canonicalNameCmp(qname, next) < 0
	}
	// Wrap-around: this is the last NSEC and next points back at the apex.
	return canonicalNameCmp(owner, qname) < 0 || canonicalNameCmp(qname, next) < 0
}

// nsec3ProvesDenial reports whether the authenticated NSEC3 records prove the
// denial for the given response code.
func nsec3ProvesDenial(nsec3s []*dns.NSEC3, qname string, qtype uint16, rcode int) bool {
	if len(nsec3s) == 0 {
		return false
	}
	switch rcode {
	case dns.RcodeNameError:
		return nsec3ProvesNXDOMAIN(nsec3s, qname)
	case dns.RcodeSuccess:
		return nsec3ProvesNODATA(nsec3s, qname, qtype)
	}
	return false
}

// nsec3ProvesNODATA proves that qname exists but the queried type does not.
func nsec3ProvesNODATA(nsec3s []*dns.NSEC3, qname string, qtype uint16) bool {
	qname = dns.CanonicalName(qname)

	// Direct match with the type (and CNAME) absent.
	for _, r := range nsec3s {
		if r.Match(qname) {
			return !slices.Contains(r.TypeBitMap, qtype) && !slices.Contains(r.TypeBitMap, dns.TypeCNAME)
		}
	}

	// DS NODATA via opt-out: the name is covered by an opt-out NSEC3, proving
	// no signed DS exists (RFC 5155 §6).
	if qtype == dns.TypeDS && nsec3OptOutCovers(nsec3s, qname) {
		return true
	}

	// Wildcard NODATA: closest encloser exists, next closer is covered, and the
	// wildcard matches with the type absent.
	ce, nextCloser, ok := nsec3ClosestEncloser(nsec3s, qname)
	if ok && nsec3CoverAny(nsec3s, nextCloser) {
		wildcard := "*." + ce
		for _, r := range nsec3s {
			if r.Match(wildcard) {
				return !slices.Contains(r.TypeBitMap, qtype) && !slices.Contains(r.TypeBitMap, dns.TypeCNAME)
			}
		}
	}
	return false
}

// nsec3ProvesNXDOMAIN proves qname does not exist via the closest encloser
// proof: a matching NSEC3 for the closest encloser, a covering NSEC3 for the
// next closer name, and a covering NSEC3 for the wildcard at the closest
// encloser. Opt-out on the next closer admits an (insecure) delegation.
// RFC 5155 §8.4, §8.7.
func nsec3ProvesNXDOMAIN(nsec3s []*dns.NSEC3, qname string) bool {
	ce, nextCloser, ok := nsec3ClosestEncloser(nsec3s, qname)
	if !ok {
		return false
	}
	if !nsec3CoverAny(nsec3s, nextCloser) {
		return false
	}
	if nsec3CoverAny(nsec3s, "*."+ce) {
		return true
	}
	// Opt-out: the next closer is covered by an opt-out NSEC3, so the name may
	// be an unsigned delegation; the negative answer is acceptable.
	return nsec3OptOutCovers(nsec3s, nextCloser)
}

// nsec3ClosestEncloser finds the longest ancestor of qname matched by an NSEC3
// record and returns it together with the next closer name (that ancestor with
// one more label from qname). The closest encloser is always a proper ancestor
// of qname.
func nsec3ClosestEncloser(nsec3s []*dns.NSEC3, qname string) (ce, nextCloser string, ok bool) {
	qname = dns.CanonicalName(qname)
	n := dns.CountLabel(qname)
	for k := n - 1; k >= 0; k-- {
		candidate := lastNLabels(qname, k)
		if nsec3MatchAny(nsec3s, candidate) {
			return candidate, lastNLabels(qname, k+1), true
		}
	}
	return "", "", false
}

func nsec3MatchAny(nsec3s []*dns.NSEC3, name string) bool {
	for _, r := range nsec3s {
		if r.Match(name) {
			return true
		}
	}
	return false
}

func nsec3CoverAny(nsec3s []*dns.NSEC3, name string) bool {
	for _, r := range nsec3s {
		if r.Cover(name) {
			return true
		}
	}
	return false
}

func nsec3OptOutCovers(nsec3s []*dns.NSEC3, name string) bool {
	for _, r := range nsec3s {
		if r.Flags&1 == 1 && r.Cover(name) {
			return true
		}
	}
	return false
}

// lastNLabels returns the rightmost n labels of name as a fully-qualified
// name, or the root when n <= 0.
func lastNLabels(name string, n int) string {
	if n <= 0 {
		return "."
	}
	labels := dns.SplitDomainName(name)
	if n >= len(labels) {
		return dns.CanonicalName(name)
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}

// canonicalNameCmp compares two domain names in DNSSEC canonical order
// (RFC 4034 §6.1): label by label from the rightmost, comparing the raw
// (unescaped, lowercased) octets of each label. A name that is a proper suffix
// of the other sorts first. Returns -1, 0, or 1.
func canonicalNameCmp(a, b string) int {
	al := canonicalLabels(a)
	bl := canonicalLabels(b)
	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		if c := bytes.Compare(al[i], bl[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case i < 0 && j < 0:
		return 0
	case i < 0:
		return -1
	default:
		return 1
	}
}

// canonicalLabels splits a name into its raw (unescaped) lowercased labels,
// excluding the root label.
func canonicalLabels(name string) [][]byte {
	name = dns.CanonicalName(name)
	if name == "." {
		return nil
	}
	var labels [][]byte
	cur := []byte{}
	for i := 0; i < len(name); {
		switch c := name[i]; {
		case c == '\\':
			switch {
			case i+3 < len(name) && isDigit(name[i+1]) && isDigit(name[i+2]) && isDigit(name[i+3]):
				cur = append(cur, (name[i+1]-'0')*100+(name[i+2]-'0')*10+(name[i+3]-'0'))
				i += 4
			case i+1 < len(name):
				cur = append(cur, name[i+1])
				i += 2
			default:
				i++
			}
		case c == '.':
			labels = append(labels, cur)
			cur = []byte{}
			i++
		default:
			cur = append(cur, c)
			i++
		}
	}
	return labels
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
