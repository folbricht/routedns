package dnssec

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestBuildChainOfTrustRejectsUnsignedDS exercises the on-path attacker
// scenario where the RRSIG covering a DS RRset is stripped (or never
// supplied). The attacker serves a forged DS that hashes their own KSK,
// signs their own DNSKEY set, and signs a forged answer. Without a
// covering RRSIG on the DS RRset the chain of trust is broken and
// validation must fail.
func TestBuildChainOfTrustRejectsUnsignedDS(t *testing.T) {
	now := time.Now()

	// Legitimate root keys — the trust anchor.
	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, _ := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	// Attacker-controlled keys for the victim zone.
	attackerKSK, attackerKSKpriv := genKey(t, "victim.", 257)
	attackerZSK, attackerZSKpriv := genKey(t, "victim.", 256)
	attackerDNSKEYSig := signRRset(t, attackerKSK, attackerKSKpriv, now, []dns.RR{attackerZSK, attackerKSK})

	// Forged DS for victim. that hashes the attacker KSK. This is what an
	// honest root would refuse to sign — and the attacker cannot sign it
	// with the root ZSK — so it is served WITHOUT an RRSIG.
	attackerDS := attackerKSK.ToDS(dns.SHA256)
	require.NotNil(t, attackerDS)

	// Forged answer signed by the attacker's ZSK.
	forgedA, _ := dns.NewRR("victim. 300 IN A 6.6.6.6")
	forgedASig := signRRset(t, attackerZSK, attackerZSKpriv, now, []dns.RR{forgedA})

	resolver := func(q *dns.Msg) (*dns.Msg, error) {
		a := new(dns.Msg)
		a.SetReply(q)
		name := dns.CanonicalName(q.Question[0].Name)
		switch q.Question[0].Qtype {
		case dns.TypeDNSKEY:
			switch name {
			case ".":
				a.Answer = []dns.RR{rootZSK, rootKSK, rootDNSKEYSig}
			case "victim.":
				a.Answer = []dns.RR{attackerZSK, attackerKSK, attackerDNSKEYSig}
			}
		case dns.TypeDS:
			if name == "victim." {
				a.Answer = []dns.RR{attackerDS} // no RRSIG
			}
		}
		return a, nil
	}

	v := NewValidator(WithResolver(resolver), WithTime(func() time.Time { return now }))
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	v.SetAnchor(".", rootAnchor.KeyTag, rootAnchor.Algorithm, rootAnchor.DigestType, rootAnchor.Digest)

	answer := new(dns.Msg)
	answer.SetQuestion("victim.", dns.TypeA)
	answer.Answer = []dns.RR{forgedA, forgedASig}

	err := v.Validate(answer)
	require.ErrorIs(t, err, ErrNoSignature, "unsigned DS RRset must be rejected as bogus")
}

// TestBuildChainOfTrustAcceptsSignedDS is the positive counterpart: when
// the parent zone properly signs the child DS RRset, validation succeeds.
func TestBuildChainOfTrustAcceptsSignedDS(t *testing.T) {
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, rootZSKpriv := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	childKSK, childKSKpriv := genKey(t, "child.", 257)
	childZSK, childZSKpriv := genKey(t, "child.", 256)
	childDNSKEYSig := signRRset(t, childKSK, childKSKpriv, now, []dns.RR{childZSK, childKSK})

	childDS := childKSK.ToDS(dns.SHA256)
	require.NotNil(t, childDS)
	childDSSig := signRRset(t, rootZSK, rootZSKpriv, now, []dns.RR{childDS})

	childA, _ := dns.NewRR("child. 300 IN A 1.2.3.4")
	childASig := signRRset(t, childZSK, childZSKpriv, now, []dns.RR{childA})

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

	answer := new(dns.Msg)
	answer.SetQuestion("child.", dns.TypeA)
	answer.Answer = []dns.RR{childA, childASig}

	require.NoError(t, v.Validate(answer))
}

// TestValidateRejectsStrippedRRSIGWithEmptyDS reproduces the downgrade attack
// where an on-path attacker strips the RRSIG from a signed zone's answer and
// then replies NODATA to the validator's follow-up DS query. Without an
// authenticated NSEC/NSEC3 denial, the empty DS response must be treated as
// bogus, not as proof of an insecure delegation.
func TestValidateRejectsStrippedRRSIGWithEmptyDS(t *testing.T) {
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, _ := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	// Forged answer for a zone that is actually signed. Attacker strips the
	// covering RRSIG so the validator falls into checkInsecureDelegation.
	forgedA, _ := dns.NewRR("signed. 300 IN A 6.6.6.6")

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
			// Attacker returns empty NOERROR with no NSEC/NSEC3 in
			// authority — an unauthenticated denial.
		}
		return a, nil
	}

	v := NewValidator(WithResolver(resolver), WithTime(func() time.Time { return now }))
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	v.SetAnchor(".", rootAnchor.KeyTag, rootAnchor.Algorithm, rootAnchor.DigestType, rootAnchor.Digest)

	answer := new(dns.Msg)
	answer.SetQuestion("signed.", dns.TypeA)
	answer.Answer = []dns.RR{forgedA}

	err := v.Validate(answer)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrInsecureDelegation),
		"unauthenticated empty DS must be bogus, not an insecure delegation; got %v", err)
}

// TestBuildChainOfTrustRejectsEmptyDSWithoutDenial covers the second downgrade
// path: the answer carries an attacker-signed RRSIG, so validation enters
// buildChainOfTrust for the signer zone. The attacker then returns an empty DS
// response for that zone. Without authenticated denial this must be bogus.
func TestBuildChainOfTrustRejectsEmptyDSWithoutDenial(t *testing.T) {
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, _ := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	attackerKSK, attackerKSKpriv := genKey(t, "victim.", 257)
	attackerZSK, attackerZSKpriv := genKey(t, "victim.", 256)
	attackerDNSKEYSig := signRRset(t, attackerKSK, attackerKSKpriv, now, []dns.RR{attackerZSK, attackerKSK})

	forgedA, _ := dns.NewRR("victim. 300 IN A 6.6.6.6")
	forgedASig := signRRset(t, attackerZSK, attackerZSKpriv, now, []dns.RR{forgedA})

	resolver := func(q *dns.Msg) (*dns.Msg, error) {
		a := new(dns.Msg)
		a.SetReply(q)
		name := dns.CanonicalName(q.Question[0].Name)
		switch q.Question[0].Qtype {
		case dns.TypeDNSKEY:
			switch name {
			case ".":
				a.Answer = []dns.RR{rootZSK, rootKSK, rootDNSKEYSig}
			case "victim.":
				a.Answer = []dns.RR{attackerZSK, attackerKSK, attackerDNSKEYSig}
			}
		case dns.TypeDS:
			// Attacker returns empty NOERROR for victim. DS — no NSEC/NSEC3.
		}
		return a, nil
	}

	v := NewValidator(WithResolver(resolver), WithTime(func() time.Time { return now }))
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	v.SetAnchor(".", rootAnchor.KeyTag, rootAnchor.Algorithm, rootAnchor.DigestType, rootAnchor.Digest)

	answer := new(dns.Msg)
	answer.SetQuestion("victim.", dns.TypeA)
	answer.Answer = []dns.RR{forgedA, forgedASig}

	err := v.Validate(answer)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrInsecureDelegation),
		"unauthenticated empty DS in chain must be bogus, not insecure; got %v", err)
}

// TestValidateAcceptsProvenInsecureDelegation is the positive counterpart:
// the parent zone serves a signed NSEC record proving no DS exists for the
// child. This is a legitimate insecure delegation and must yield
// ErrInsecureDelegation so the caller can pass the unsigned answer through.
func TestValidateAcceptsProvenInsecureDelegation(t *testing.T) {
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, rootZSKpriv := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	// Root-signed NSEC at "unsigned." proving the delegation exists (NS in
	// bitmap) but has no DS.
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "unsigned.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "\x00.unsigned.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	nsecSig := signRRset(t, rootZSK, rootZSKpriv, now, []dns.RR{nsec})

	unsignedA, _ := dns.NewRR("unsigned. 300 IN A 1.2.3.4")

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
	answer.SetQuestion("unsigned.", dns.TypeA)
	answer.Answer = []dns.RR{unsignedA}

	err := v.Validate(answer)
	require.ErrorIs(t, err, ErrInsecureDelegation,
		"NSEC-proven absence of DS must yield ErrInsecureDelegation; got %v", err)
}

// TestValidateRejectsForgedNSECDenial ensures an attacker cannot fabricate an
// NSEC denial signed with their own key — the NSEC RRSIG must chain to the
// trust anchor via the parent zone.
func TestValidateRejectsForgedNSECDenial(t *testing.T) {
	now := time.Now()

	rootKSK, rootKSKpriv := genKey(t, ".", 257)
	rootZSK, _ := genKey(t, ".", 256)
	rootDNSKEYSig := signRRset(t, rootKSK, rootKSKpriv, now, []dns.RR{rootZSK, rootKSK})

	// Attacker generates their own key claiming to be the root ZSK and signs
	// an NSEC denying DS for "signed.".
	fakeRootZSK, fakeRootZSKpriv := genKey(t, ".", 256)
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "signed.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "\x00.signed.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	forgedNSECSig := signRRset(t, fakeRootZSK, fakeRootZSKpriv, now, []dns.RR{nsec})

	forgedA, _ := dns.NewRR("signed. 300 IN A 6.6.6.6")

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
			if name == "signed." {
				a.Ns = []dns.RR{nsec, forgedNSECSig}
			}
		}
		return a, nil
	}

	v := NewValidator(WithResolver(resolver), WithTime(func() time.Time { return now }))
	rootAnchor := rootKSK.ToDS(dns.SHA256)
	v.SetAnchor(".", rootAnchor.KeyTag, rootAnchor.Algorithm, rootAnchor.DigestType, rootAnchor.Digest)

	answer := new(dns.Msg)
	answer.SetQuestion("signed.", dns.TypeA)
	answer.Answer = []dns.RR{forgedA}

	err := v.Validate(answer)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrInsecureDelegation),
		"NSEC signed by an untrusted key must be rejected; got %v", err)
}

// genKey creates an ECDSAP256SHA256 DNSKEY for the given owner and flags
// (256 = ZSK, 257 = KSK) and returns the public DNSKEY plus its private signer.
func genKey(t *testing.T, owner string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	require.NoError(t, err)
	signer, ok := priv.(crypto.Signer)
	require.True(t, ok, "generated key must implement crypto.Signer")
	return k, signer
}

// signRRset produces an RRSIG over rrset using the given DNSKEY/private pair.
func signRRset(t *testing.T, key *dns.DNSKEY, priv crypto.Signer, now time.Time, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   rrset[0].Header().Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    rrset[0].Header().Ttl,
		},
		Algorithm:  key.Algorithm,
		SignerName: key.Hdr.Name,
		KeyTag:     key.KeyTag(),
		Inception:  uint32(now.Add(-time.Hour).Unix()),
		Expiration: uint32(now.Add(time.Hour).Unix()),
	}
	require.NoError(t, sig.Sign(priv, rrset))
	return sig
}
