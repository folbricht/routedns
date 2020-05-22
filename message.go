package rdns

import "github.com/miekg/dns"

// Return the query name from a DNS query.
func qName(q *dns.Msg) string {
	if len(q.Question) == 0 {
		return ""
	}
	return q.Question[0].Name
}

// Returns a NXDOMAIN answer for a query.
func nxdomain(q *dns.Msg) *dns.Msg {
	a := new(dns.Msg)
	a.SetReply(q)
	a.SetRcode(q, dns.RcodeNameError)
	return a
}
