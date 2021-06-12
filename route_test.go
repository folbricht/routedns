package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRoute(t *testing.T) {
	tests := []struct {
		rName   string
		rType   []string
		rClass  string
		rInvert bool
		qName   string
		qType   uint16
		qClass  uint16
		match   bool
	}{
		{
			rName: "\\.google\\.com$",
			qType: dns.TypeA,
			qName: "bla.google.com",
			match: true,
		},
		{
			rName: "\\.google\\.com$",
			qType: dns.TypeA,
			qName: "google.com",
			match: false,
		},
		{
			rType: []string{"MX"},
			rName: "google\\.com$",
			qType: dns.TypeA,
			qName: "google.com",
			match: false,
		},
		{
			rType: []string{"MX", "A"},
			rName: "google\\.com$",
			qType: dns.TypeA,
			qName: "google.com",
			match: true,
		},
		{
			rType: []string{"MX"},
			rName: "google\\.com$",
			qType: dns.TypeMX,
			qName: "google.com",
			match: true,
		},
		{
			rType:   []string{"MX"},
			rName:   "google\\.com$",
			rInvert: true,
			qType:   dns.TypeMX,
			qName:   "google.com",
			match:   false,
		},
		{
			rClass: "INET",
			rType:  []string{"A"},
			rName:  "google\\.com$",
			qClass: dns.ClassANY,
			qType:  dns.TypeA,
			qName:  "google.com",
			match:  false,
		},
		{
			rClass: "INET",
			rType:  []string{"A"},
			rName:  "google\\.com$",
			qClass: dns.ClassINET,
			qType:  dns.TypeA,
			qName:  "google.com",
			match:  true,
		},
	}
	for _, test := range tests {
		r, err := NewRoute(test.rName, test.rClass, test.rType, nil, "", "", "", &TestResolver{})
		require.NoError(t, err)
		r.Invert(test.rInvert)

		q := new(dns.Msg)
		q.Question = make([]dns.Question, 1)
		q.Question[0] = dns.Question{Name: test.qName, Qtype: test.qType, Qclass: test.qClass}

		match := r.match(q, ClientInfo{})
		require.Equal(t, test.match, match)
	}
}
