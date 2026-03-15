package rdns

import (
	"errors"
	"expvar"

	"github.com/folbricht/routedns/dnssec"
	"github.com/miekg/dns"
)

// DNSSECValidator passes a query to the upstream resolver and
// validates the response with DNSSEC.
type DNSSECValidator struct {
	id        string
	resolver  Resolver
	validator *dnssec.Validator
	DNSSECValidatorOptions

	metrics *dnssecMetrics
}

// DNSSECValidatorOptions holds configuration for the DNSSEC validator.
type DNSSECValidatorOptions struct {
	TrustAnchors []TrustAnchor
	LogOnly      bool // Log validation failures without returning SERVFAIL
}

// TrustAnchor represents a DNSSEC trust anchor (typically the root KSK).
type TrustAnchor struct {
	Owner      string
	Digest     string
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
}

type dnssecMetrics struct {
	success *expvar.Int
	failure *expvar.Int
}

var _ Resolver = &DNSSECValidator{}

// IANA root trust anchors (KSK-2017 and KSK-2024)
// From https://data.iana.org/root-anchors/root-anchors.xml
var defaultTrustAnchors = []TrustAnchor{
	{
		Owner:      ".",
		KeyTag:     20326,
		Algorithm:  8, // RSASHA256
		DigestType: 2, // SHA-256
		Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	},
	{
		Owner:      ".",
		KeyTag:     38696,
		Algorithm:  8, // RSASHA256
		DigestType: 2, // SHA-256
		Digest:     "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
	},
}

// NewDNSSECValidator returns a new instance of a DNSSEC validator.
func NewDNSSECValidator(id string, resolver Resolver, opt DNSSECValidatorOptions) (*DNSSECValidator, error) {
	v := dnssec.NewValidator(
		dnssec.WithResolver(func(q *dns.Msg) (*dns.Msg, error) {
			return resolver.Resolve(q, ClientInfo{})
		}),
	)

	anchors := opt.TrustAnchors
	if len(anchors) == 0 {
		anchors = defaultTrustAnchors
	}
	for _, ta := range anchors {
		v.SetAnchor(ta.Owner, ta.KeyTag, ta.Algorithm, ta.DigestType, ta.Digest)
	}

	return &DNSSECValidator{
		id:                     id,
		resolver:               resolver,
		validator:              v,
		DNSSECValidatorOptions: opt,
		metrics: &dnssecMetrics{
			success: getVarInt("dnssec", id, "validation-success"),
			failure: getVarInt("dnssec", id, "validation-failure"),
		},
	}, nil
}

// Resolve a DNS query, then validate the response with DNSSEC.
func (r *DNSSECValidator) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)

	// Save the client's EDNS0/DO state before we modify the query
	clientEdns0 := q.IsEdns0()
	clientHadEdns0 := clientEdns0 != nil
	clientSetDo := clientHadEdns0 && clientEdns0.Do()
	qtype := q.Question[0].Qtype

	// Work on a copy so we don't mutate the caller's query
	qUpstream := q.Copy()

	// Ensure the DO (DNSSEC OK) bit is set
	edns0 := qUpstream.IsEdns0()
	if edns0 == nil {
		qUpstream.SetEdns0(4096, true)
	} else {
		edns0.SetUDPSize(4096)
		edns0.SetDo()
	}

	answer, err := r.resolver.Resolve(qUpstream, ci)
	if err != nil || answer == nil {
		return answer, err
	}

	// Only validate successful responses
	if answer.Rcode != dns.RcodeSuccess && answer.Rcode != dns.RcodeNameError {
		stripDNSSEC(answer, clientSetDo, clientHadEdns0, qtype)
		return answer, nil
	}

	if err := r.validator.Validate(answer); err != nil {
		if errors.Is(err, dnssec.ErrInsecureDelegation) {
			log.Debug("insecure delegation, passing through", "error", err)
			stripDNSSEC(answer, clientSetDo, clientHadEdns0, qtype)
			return answer, nil
		}
		r.metrics.failure.Add(1)
		log.Error("dnssec validation failed", "error", err)
		if !r.LogOnly {
			return servfail(q), nil
		}
		stripDNSSEC(answer, clientSetDo, clientHadEdns0, qtype)
		return answer, nil
	}

	r.metrics.success.Add(1)
	answer.AuthenticatedData = true
	stripDNSSEC(answer, clientSetDo, clientHadEdns0, qtype)
	return answer, nil
}

// stripDNSSEC removes DNSSEC records from the response if the client
// did not set the DO bit. Per RFC 4035 Section 3.2.1.
func stripDNSSEC(answer *dns.Msg, clientSetDo, clientHadEdns0 bool, qtype uint16) {
	if clientSetDo {
		return
	}
	answer.Answer = filterDNSSECRR(answer.Answer, qtype)
	answer.Ns = filterDNSSECRR(answer.Ns, qtype)
	answer.Extra = filterDNSSECRR(answer.Extra, qtype)

	if !clientHadEdns0 {
		// Remove OPT record entirely
		filtered := answer.Extra[:0]
		for _, rr := range answer.Extra {
			if _, ok := rr.(*dns.OPT); !ok {
				filtered = append(filtered, rr)
			}
		}
		answer.Extra = filtered
	} else {
		// Client had EDNS0 but DO=false: clear DO in the response
		if opt := answer.IsEdns0(); opt != nil {
			opt.Hdr.Ttl &^= 1 << 15
		}
	}
}

// filterDNSSECRR removes RRSIG, NSEC, and NSEC3 records from a slice,
// preserving OPT pseudo-records and records matching the original query type.
func filterDNSSECRR(rrs []dns.RR, qtype uint16) []dns.RR {
	filtered := rrs[:0]
	for _, rr := range rrs {
		// Always keep OPT pseudo-records (handled separately)
		if _, ok := rr.(*dns.OPT); ok {
			filtered = append(filtered, rr)
			continue
		}
		rrtype := rr.Header().Rrtype
		// Keep records that match the original query type
		if rrtype == qtype {
			filtered = append(filtered, rr)
			continue
		}
		// Strip DNSSEC-specific record types
		if rrtype == dns.TypeRRSIG || rrtype == dns.TypeNSEC || rrtype == dns.TypeNSEC3 {
			continue
		}
		filtered = append(filtered, rr)
	}
	return filtered
}

func (r *DNSSECValidator) String() string {
	return r.id
}
