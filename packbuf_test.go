package rdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A message that outgrows the pooled buffer still packs whole, and the larger
// buffer it needed is the one kept for next time rather than being dropped.
func TestPackToPoolGrows(t *testing.T) {
	a := new(dns.Msg)
	a.SetQuestion("example.com.", dns.TypeTXT)
	for i := range 20 {
		a.Answer = append(a.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat(string(rune('a'+i)), 255)},
		})
	}

	wire, bufPtr, err := packToPool(a)
	require.NoError(t, err)
	require.Greater(t, len(wire), 2048, "the message has to outgrow the pooled buffer to test anything")

	got := new(dns.Msg)
	require.NoError(t, got.Unpack(wire))
	require.Len(t, got.Answer, 20)

	require.GreaterOrEqual(t, cap(*bufPtr), len(wire))
	putPackBuf(bufPtr)
}
