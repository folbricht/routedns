package rdns

import "github.com/miekg/dns"

// Return the query name from a DNS query.
func qName(q *dns.Msg) string {
	if len(q.Question) == 0 {
		return ""
	}
	return q.Question[0].Name
}
