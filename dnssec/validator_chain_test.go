package dnssec

import (
	"crypto"
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
