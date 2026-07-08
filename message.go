package rdns

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Confirms that a response from an upstream answers the question that was
// asked. As per https://tools.ietf.org/html/rfc7858#section-3.3 and RFC 5452
// section 9.1, the response to a query that carried a Question must echo it
// back. A response with an empty Question section (QDCOUNT=0) is rejected
// rather than accepted - on datagram transports, skipping the check would
// leave only the 16-bit transaction ID and source port as anti-spoofing
// protection. On authenticated transports it guards against a misbehaving
// upstream, and stops a mismatched answer from being stored in a cache under
// the key of the question that was actually asked.
//
// Queries without a Question section are not validated. The name comparison is
// case-insensitive; RouteDNS does not use DNS-0x20, so case carries no
// information that needs preserving here.
func validateResponseQuestion(q, a *dns.Msg) error {
	if len(q.Question) == 0 {
		return nil
	}
	question := q.Question[0]
	if len(a.Question) == 0 {
		return fmt.Errorf("expected answer for %s, got response with empty question section", question.String())
	}
	answer := a.Question[0]
	if !strings.EqualFold(answer.Name, question.Name) || answer.Qclass != question.Qclass || answer.Qtype != question.Qtype {
		return fmt.Errorf("expected answer for %s, got %s", question.String(), answer.String())
	}
	return nil
}

// Return the query name from a DNS query.
func qName(q *dns.Msg) string {
	if len(q.Question) == 0 {
		return ""
	}
	return q.Question[0].Name
}

// Returns the string representation of the query type.
func qType(q *dns.Msg) string {
	if len(q.Question) == 0 {
		return ""
	}
	return dns.TypeToString[q.Question[0].Qtype]
}

// Return the result code name from a DNS response.
func rCode(r *dns.Msg) string {
	if result, ok := dns.RcodeToString[r.Rcode]; ok {
		return result
	}
	return strconv.Itoa(r.Rcode)
}

// Returns a NXDOMAIN answer for a query.
func nxdomain(q *dns.Msg) *dns.Msg {
	return responseWithCode(q, dns.RcodeNameError)
}

// Returns a SERVFAIL answer for a query.
func servfail(q *dns.Msg) *dns.Msg {
	return responseWithCode(q, dns.RcodeServerFailure)
}

// Returns a REFUSED answer for a query.
func refused(q *dns.Msg) *dns.Msg {
	return responseWithCode(q, dns.RcodeRefused)
}

// Build a response for a query with the given responce code.
func responseWithCode(q *dns.Msg, rcode int) *dns.Msg {
	a := new(dns.Msg)
	a.SetRcode(q, rcode)
	a.RecursionAvailable = true // we support recursion (even if we didn't actually do any)
	return a
}

// Answers a PTR query with a name
func ptr(q *dns.Msg, names []string) *dns.Msg {
	a := new(dns.Msg)
	a.SetReply(q)
	a.RecursionAvailable = true // we support recursion (even if we didn't actually do any)
	answer := make([]dns.RR, 0, len(names))
	for _, name := range names {
		rr := &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   q.Question[0].Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ptr: dns.Fqdn(name),
		}
		answer = append(answer, rr)
	}
	a.Answer = answer
	return a
}

// Changes the UDP size in the EDNS0 record and returns a
// copy of the query. Adds an OPT record if there isn't one
// already. If size is 0, the original query is returned.
func setUDPSize(q *dns.Msg, size uint16) *dns.Msg {
	if size == 0 {
		return q
	}
	copy := q.Copy()
	// Set the EDNS0 size. Adds an OPT record if there isn't
	// one already
	edns0 := copy.IsEdns0()
	if edns0 != nil {
		edns0.SetUDPSize(size)
	} else {
		copy.SetEdns0(size, false)
	}
	return copy
}
