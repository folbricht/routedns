package rdns

import (
	"expvar"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// DNS64 is a resolver that synthesizes AAAA records from A records for
// IPv6-only clients using NAT64 (RFC 6147). When an AAAA query returns
// no AAAA answers, it falls back to an A query and embeds the IPv4
// addresses into configurable IPv6 prefixes per RFC 6052.
type DNS64 struct {
	id       string
	resolver Resolver
	DNS64Options
	prefixes []dns64Prefix
	metrics  *dns64Metrics
}

// DNS64Options contains configuration for the DNS64 modifier.
type DNS64Options struct {
	// IPv6 prefixes used for address synthesis per RFC 6052.
	// Each string is a CIDR like "64:ff9b::/96".
	// Only prefix lengths /32, /40, /48, /56, /64, /96 are allowed.
	// Default: ["64:ff9b::/96"] (well-known prefix)
	Prefixes []string
}

type dns64Prefix struct {
	ip        net.IP // 16-byte IPv6 network address
	prefixLen int    // one of 32, 40, 48, 56, 64, 96
}

type dns64Metrics struct {
	query    *expvar.Int
	synth    *expvar.Int
	passthru *expvar.Int
	err      *expvar.Int
}

var _ Resolver = &DNS64{}

// NewDNS64 returns a new DNS64 modifier instance.
func NewDNS64(id string, resolver Resolver, opt DNS64Options) (*DNS64, error) {
	if len(opt.Prefixes) == 0 {
		opt.Prefixes = []string{"64:ff9b::/96"}
	}
	prefixes, err := parseDNS64Prefixes(opt.Prefixes)
	if err != nil {
		return nil, err
	}
	return &DNS64{
		id:           id,
		resolver:     resolver,
		DNS64Options: opt,
		prefixes:     prefixes,
		metrics: &dns64Metrics{
			query:    getVarInt("dns64", id, "query"),
			synth:    getVarInt("dns64", id, "synth"),
			passthru: getVarInt("dns64", id, "passthru"),
			err:      getVarInt("dns64", id, "err"),
		},
	}, nil
}

// Resolve a DNS query. For AAAA queries without native AAAA answers,
// synthesizes AAAA records from A records using the configured prefixes.
func (r *DNS64) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	question := q.Question[0]

	// Non-AAAA queries pass through unchanged
	if question.Qtype != dns.TypeAAAA {
		r.metrics.passthru.Add(1)
		return r.resolver.Resolve(q, ci)
	}

	r.metrics.query.Add(1)
	log := logger(r.id, q, ci)

	// Forward the AAAA query upstream
	answer, err := r.resolver.Resolve(q, ci)
	if err != nil {
		r.metrics.err.Add(1)
		return answer, err
	}
	if answer == nil {
		return answer, nil
	}

	// Non-success responses (including NXDOMAIN) pass through
	if answer.Rcode != dns.RcodeSuccess {
		r.metrics.passthru.Add(1)
		return answer, nil
	}

	// If upstream returned AAAA records, pass through
	if hasAAAARecords(answer) {
		r.metrics.passthru.Add(1)
		log.Debug("upstream has native AAAA records, passing through")
		return answer, nil
	}

	// No AAAA records — query for A records and synthesize
	log.Debug("no AAAA records from upstream, querying for A records")

	aQuery := q.Copy()
	aQuery.Question[0].Qtype = dns.TypeA

	aAnswer, err := r.resolver.Resolve(aQuery, ci)
	if err != nil {
		r.metrics.err.Add(1)
		return answer, nil // Return original NODATA on error
	}
	if aAnswer == nil || aAnswer.Rcode != dns.RcodeSuccess {
		r.metrics.passthru.Add(1)
		return answer, nil // Return original NODATA
	}

	// Synthesize AAAA records from A records
	synthesized := r.synthesizeAAAA(aAnswer, question)
	if len(synthesized) == 0 {
		r.metrics.passthru.Add(1)
		return answer, nil
	}

	r.metrics.synth.Add(1)
	log.Debug("synthesized AAAA records from A records", "count", len(synthesized))

	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.RecursionAvailable = answer.RecursionAvailable
	resp.Answer = synthesized
	resp.Ns = aAnswer.Ns
	resp.Extra = aAnswer.Extra
	return resp, nil
}

func (r *DNS64) String() string {
	return r.id
}

// synthesizeAAAA creates AAAA records from A records in the response.
func (r *DNS64) synthesizeAAAA(aAnswer *dns.Msg, question dns.Question) []dns.RR {
	var result []dns.RR
	for _, rr := range aAnswer.Answer {
		aRecord, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ipv4 := aRecord.A.To4()
		if ipv4 == nil {
			continue
		}
		for _, prefix := range r.prefixes {
			ipv6 := synthesizeIPv6(prefix, ipv4)
			result = append(result, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  question.Qclass,
					Ttl:    aRecord.Hdr.Ttl,
				},
				AAAA: ipv6,
			})
		}
	}
	return result
}

// hasAAAARecords returns true if the message contains any AAAA answer records.
func hasAAAARecords(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			return true
		}
	}
	return false
}

// synthesizeIPv6 embeds an IPv4 address into an IPv6 prefix per RFC 6052
// Section 2.2. Bits 64-71 (byte index 8) are always zero for prefix
// lengths shorter than /96.
func synthesizeIPv6(prefix dns64Prefix, ipv4 net.IP) net.IP {
	ipv4 = ipv4.To4()
	ipv6 := make(net.IP, net.IPv6len)
	copy(ipv6, prefix.ip)

	switch prefix.prefixLen {
	case 96:
		ipv6[12] = ipv4[0]
		ipv6[13] = ipv4[1]
		ipv6[14] = ipv4[2]
		ipv6[15] = ipv4[3]
	case 64:
		ipv6[8] = 0
		ipv6[9] = ipv4[0]
		ipv6[10] = ipv4[1]
		ipv6[11] = ipv4[2]
		ipv6[12] = ipv4[3]
	case 56:
		ipv6[7] = ipv4[0]
		ipv6[8] = 0
		ipv6[9] = ipv4[1]
		ipv6[10] = ipv4[2]
		ipv6[11] = ipv4[3]
	case 48:
		ipv6[6] = ipv4[0]
		ipv6[7] = ipv4[1]
		ipv6[8] = 0
		ipv6[9] = ipv4[2]
		ipv6[10] = ipv4[3]
	case 40:
		ipv6[5] = ipv4[0]
		ipv6[6] = ipv4[1]
		ipv6[7] = ipv4[2]
		ipv6[8] = 0
		ipv6[9] = ipv4[3]
	case 32:
		ipv6[4] = ipv4[0]
		ipv6[5] = ipv4[1]
		ipv6[6] = ipv4[2]
		ipv6[7] = ipv4[3]
		ipv6[8] = 0
	}

	return ipv6
}

// parseDNS64Prefixes parses and validates DNS64 prefix strings.
func parseDNS64Prefixes(prefixStrs []string) ([]dns64Prefix, error) {
	validLengths := map[int]bool{32: true, 40: true, 48: true, 56: true, 64: true, 96: true}

	var prefixes []dns64Prefix
	for _, s := range prefixStrs {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS64 prefix %q: %w", s, err)
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 128 {
			return nil, fmt.Errorf("DNS64 prefix %q must be an IPv6 CIDR", s)
		}
		if !validLengths[ones] {
			return nil, fmt.Errorf("DNS64 prefix %q has unsupported prefix length /%d; must be /32, /40, /48, /56, /64, or /96", s, ones)
		}
		prefixes = append(prefixes, dns64Prefix{
			ip:        ipNet.IP.To16(),
			prefixLen: ones,
		})
	}
	return prefixes, nil
}
