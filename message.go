package rdns

import (
	"strconv"

	"github.com/miekg/dns"
)

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
	return a
}

// Answers a PTR query with a name
func ptr(q *dns.Msg, names []string) *dns.Msg {
	a := new(dns.Msg)
	a.SetReply(q)
	a.RecursionAvailable = q.RecursionDesired
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
		q.SetEdns0(size, false)
	}
	return copy
}
