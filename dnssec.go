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

// IANA root KSK-2017 trust anchor (key tag 20326)
var defaultTrustAnchors = []TrustAnchor{
	{
		Owner:      ".",
		KeyTag:     20326,
		Algorithm:  8, // RSASHA256
		DigestType: 2, // SHA-256
		Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
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

	// Ensure the DO (DNSSEC OK) bit is set
	edns0 := q.IsEdns0()
	if edns0 == nil {
		q.SetEdns0(4096, true)
	} else {
		edns0.SetUDPSize(4096)
		edns0.SetDo()
	}

	answer, err := r.resolver.Resolve(q, ci)
	if err != nil || answer == nil {
		return answer, err
	}

	// Only validate successful responses
	if answer.Rcode != dns.RcodeSuccess && answer.Rcode != dns.RcodeNameError {
		return answer, nil
	}

	if err := r.validator.Validate(answer); err != nil {
		if errors.Is(err, dnssec.ErrInsecureDelegation) {
			log.Debug("insecure delegation, passing through", "error", err)
			return answer, nil
		}
		r.metrics.failure.Add(1)
		log.Error("dnssec validation failed", "error", err)
		if !r.LogOnly {
			return servfail(q), nil
		}
		return answer, nil
	}

	r.metrics.success.Add(1)
	return answer, nil
}

func (r *DNSSECValidator) String() string {
	return r.id
}
