package dnssec

import (
	"crypto"
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// denialEnv is a signed root -> child. chain of trust with a mock resolver,
// used by the denial-of-existence tests. Tests craft the authority section of
// a negative response and validate it against this environment.
type denialEnv struct {
	v            *Validator
	now          time.Time
	childZSK     *dns.DNSKEY
	childZSKpriv crypto.Signer
}

// newSignedChildEnv builds a validator anchored at a generated root key, with
// "child." properly delegated and signed (DS + DNSKEY), served by a mock
// resolver. The child ZSK is returned so callers can sign NSEC/NSEC3 proofs.
func newSignedChildEnv(t *testing.T) denialEnv {
	t.Helper()
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, rootZSKpriv := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	childKSK, childKSKpriv := genKey(t, "child.", 257)
	childZSK, childZSKpriv := genKey(t, "child.", 256)
	childDNSKEYSig := signRRset(t, childKSK, childKSKpriv, now, []dns.RR{childZSK, childKSK})

	childDS := childKSK.ToDS(dns.SHA256)
	childDSSig := signRRset(t, rootZSK, rootZSKpriv, now, []dns.RR{childDS})

	resolver := func(q *dns.Msg) (*dns.Msg, error) {
		a := new(dns.Msg)
		a.SetReply(q)
		name := dns.CanonicalName(q.Question[0].Name)
		switch q.Question[0].Qtype {
		case dns.TypeDNSKEY:
			switch name {
			case ".":
				a.Answer = []dns.RR{rootZSK, rootKSK, rootDNSKEYSig}
			case "child.":
				a.Answer = []dns.RR{childZSK, childKSK, childDNSKEYSig}
			}
		case dns.TypeDS:
			if name == "child." {
				a.Answer = []dns.RR{childDS, childDSSig}
			}
		}
		return a, nil
	}

	v := NewValidator(WithResolver(resolver), WithTime(func() time.Time { return now }))
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	v.SetAnchor(".", rootAnchor.KeyTag, rootAnchor.Algorithm, rootAnchor.DigestType, rootAnchor.Digest)

	return denialEnv{v: v, now: now, childZSK: childZSK, childZSKpriv: childZSKpriv}
}

// TestValidateAcceptsNSECNODATA: a signed zone proves "no TLSA at child." with
// an NSEC matching the name whose bitmap omits TLSA.
func TestValidateAcceptsNSECNODATA(t *testing.T) {
	env := newSignedChildEnv(t)
	nsec, nsecSig := signNSEC(t, env.childZSK, env.childZSKpriv, env.now,
		"child.", "\x00.child.",
		[]uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY})

	answer := new(dns.Msg)
	answer.SetQuestion("child.", dns.TypeTLSA)
	answer.Rcode = dns.RcodeSuccess
	answer.Ns = []dns.RR{nsec, nsecSig}

	require.NoError(t, env.v.Validate(answer))
}

// TestValidateAcceptsNSECNXDOMAIN: an NSEC covering both the queried name and
// the wildcard at the closest encloser proves NXDOMAIN.
func TestValidateAcceptsNSECNXDOMAIN(t *testing.T) {
	env := newSignedChildEnv(t)
	// owner=child. next=z.child. spans nx.child. and *.child.
	nsec, nsecSig := signNSEC(t, env.childZSK, env.childZSKpriv, env.now,
		"child.", "z.child.",
		[]uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY})

	answer := new(dns.Msg)
	answer.SetQuestion("nx.child.", dns.TypeA)
	answer.Rcode = dns.RcodeNameError
	answer.Ns = []dns.RR{nsec, nsecSig}

	require.NoError(t, env.v.Validate(answer))
}

// TestValidateRejectsForgedNSECNODATA: an NSEC signed by a key that does not
// chain to the zone's authenticated DNSKEY must not authenticate the denial.
func TestValidateRejectsForgedNSECNODATA(t *testing.T) {
	env := newSignedChildEnv(t)
	fakeZSK, fakeZSKpriv := genKey(t, "child.", 256)
	nsec, nsecSig := signNSEC(t, fakeZSK, fakeZSKpriv, env.now,
		"child.", "\x00.child.",
		[]uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC})

	answer := new(dns.Msg)
	answer.SetQuestion("child.", dns.TypeTLSA)
	answer.Rcode = dns.RcodeSuccess
	answer.Ns = []dns.RR{nsec, nsecSig}

	err := env.v.Validate(answer)
	require.ErrorIs(t, err, ErrDenialOfExistence)
	require.NotErrorIs(t, err, ErrInsecureDelegation)
}

// TestValidateAcceptsNSEC3NODATA: an NSEC3 matching the queried name with the
// type absent proves NODATA.
func TestValidateAcceptsNSEC3NODATA(t *testing.T) {
	env := newSignedChildEnv(t)
	recs := signNSEC3Chain(t, env.childZSK, env.childZSKpriv, env.now, "child.",
		[]string{"child.", "a.child."},
		map[string][]uint16{
			"child.":   {dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY},
			"a.child.": {dns.TypeA, dns.TypeRRSIG},
		})

	answer := new(dns.Msg)
	answer.SetQuestion("child.", dns.TypeTLSA)
	answer.Rcode = dns.RcodeSuccess
	answer.Ns = recs

	require.NoError(t, env.v.Validate(answer))
}

// TestValidateAcceptsNSEC3NXDOMAIN: the closest-encloser proof (matching CE,
// covering next closer, covering wildcard) proves NXDOMAIN.
func TestValidateAcceptsNSEC3NXDOMAIN(t *testing.T) {
	env := newSignedChildEnv(t)
	recs := signNSEC3Chain(t, env.childZSK, env.childZSKpriv, env.now, "child.",
		[]string{"child.", "a.child."},
		map[string][]uint16{
			"child.":   {dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY},
			"a.child.": {dns.TypeA, dns.TypeRRSIG},
		})

	answer := new(dns.Msg)
	answer.SetQuestion("nx.child.", dns.TypeA)
	answer.Rcode = dns.RcodeNameError
	answer.Ns = recs

	require.NoError(t, env.v.Validate(answer))
}

// TestValidateAcceptsInsecureDelegationNXDOMAIN: an NXDOMAIN from a provably
// unsigned zone (parent NSEC shows no DS) is passed through as an insecure
// delegation, not treated as bogus.
func TestValidateAcceptsInsecureDelegationNXDOMAIN(t *testing.T) {
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, rootZSKpriv := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	nsec, nsecSig := signNSEC(t, rootZSK, rootZSKpriv, now,
		"unsigned.", "\x00.unsigned.",
		[]uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC})

	resolver := func(q *dns.Msg) (*dns.Msg, error) {
		a := new(dns.Msg)
		a.SetReply(q)
		name := dns.CanonicalName(q.Question[0].Name)
		switch q.Question[0].Qtype {
		case dns.TypeDNSKEY:
			if name == "." {
				a.Answer = []dns.RR{rootZSK, rootKSK, rootDNSKEYSig}
			}
		case dns.TypeDS:
			if name == "unsigned." {
				a.Ns = []dns.RR{nsec, nsecSig}
			}
		}
		return a, nil
	}

	v := NewValidator(WithResolver(resolver), WithTime(func() time.Time { return now }))
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	v.SetAnchor(".", rootAnchor.KeyTag, rootAnchor.Algorithm, rootAnchor.DigestType, rootAnchor.Digest)

	answer := new(dns.Msg)
	answer.SetQuestion("nx.unsigned.", dns.TypeA)
	answer.Rcode = dns.RcodeNameError

	err := v.Validate(answer)
	require.ErrorIs(t, err, ErrInsecureDelegation)
}

// TestValidateRejectsUnsignedNODATA reproduces the forged-NODATA scenario: a
// signed zone returns NOERROR with an empty answer (e.g. "no TLSA record")
// but the authority section carries no NSEC/NSEC3 proof of non-existence. An
// on-path attacker can use this to suppress a record (DANE/CAA downgrade).
// The validator must treat the unproven denial as bogus rather than
// authenticating it.
func TestValidateRejectsUnsignedNODATA(t *testing.T) {
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, rootZSKpriv := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	childKSK, childKSKpriv := genKey(t, "child.", 257)
	childZSK, _ := genKey(t, "child.", 256)
	childDNSKEYSig := signRRset(t, childKSK, childKSKpriv, now, []dns.RR{childZSK, childKSK})

	childDS := childKSK.ToDS(dns.SHA256)
	require.NotNil(t, childDS)
	childDSSig := signRRset(t, rootZSK, rootZSKpriv, now, []dns.RR{childDS})

	resolver := func(q *dns.Msg) (*dns.Msg, error) {
		a := new(dns.Msg)
		a.SetReply(q)
		name := dns.CanonicalName(q.Question[0].Name)
		switch q.Question[0].Qtype {
		case dns.TypeDNSKEY:
			switch name {
			case ".":
				a.Answer = []dns.RR{rootZSK, rootKSK, rootDNSKEYSig}
			case "child.":
				a.Answer = []dns.RR{childZSK, childKSK, childDNSKEYSig}
			}
		case dns.TypeDS:
			if name == "child." {
				a.Answer = []dns.RR{childDS, childDSSig}
			}
		}
		return a, nil
	}

	v := NewValidator(WithResolver(resolver), WithTime(func() time.Time { return now }))
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	v.SetAnchor(".", rootAnchor.KeyTag, rootAnchor.Algorithm, rootAnchor.DigestType, rootAnchor.Digest)

	// Forged NODATA: NOERROR, empty answer, no NSEC/NSEC3 in authority.
	answer := new(dns.Msg)
	answer.SetQuestion("child.", dns.TypeTLSA)
	answer.Rcode = dns.RcodeSuccess

	err := v.Validate(answer)
	require.ErrorIs(t, err, ErrDenialOfExistence,
		"a negative answer from a signed zone with no NSEC/NSEC3 proof must be bogus; got %v", err)
}

// signNSEC builds and signs an NSEC record at owner with the given next-domain
// name and type bitmap, signed by the supplied key.
func signNSEC(t *testing.T, key *dns.DNSKEY, priv crypto.Signer, now time.Time, owner, next string, types []uint16) (*dns.NSEC, *dns.RRSIG) {
	t.Helper()
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.CanonicalName(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.CanonicalName(next),
		TypeBitMap: types,
	}
	sig := signRRset(t, key, priv, now, []dns.RR{nsec})
	return nsec, sig
}

// signNSEC3Chain builds a complete, signed NSEC3 chain for zone over the set
// of existing owner names (SHA-1, no salt, 0 iterations). Each record's
// NextDomain points at the next owner hash in canonical order, wrapping at the
// end, so every non-existent name in the zone is covered. bitmaps supplies the
// type bitmap for each existing name. It returns the NSEC3 records interleaved
// with their RRSIGs, ready to place in the authority section.
func signNSEC3Chain(t *testing.T, key *dns.DNSKEY, priv crypto.Signer, now time.Time, zone string, existing []string, bitmaps map[string][]uint16) []dns.RR {
	t.Helper()
	zone = dns.CanonicalName(zone)

	type entry struct {
		name string
		hash string
	}
	entries := make([]entry, 0, len(existing))
	for _, n := range existing {
		entries = append(entries, entry{name: n, hash: dns.HashName(dns.CanonicalName(n), dns.SHA1, 0, "")})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].hash < entries[j].hash })

	var out []dns.RR
	for i, e := range entries {
		next := entries[(i+1)%len(entries)].hash
		n3 := &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: e.hash + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
			Hash:       dns.SHA1,
			Flags:      0,
			Iterations: 0,
			SaltLength: 0,
			Salt:       "",
			HashLength: 20,
			NextDomain: next,
			TypeBitMap: bitmaps[e.name],
		}
		sig := signRRset(t, key, priv, now, []dns.RR{n3})
		out = append(out, n3, sig)
	}
	return out
}
