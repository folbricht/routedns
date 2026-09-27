package rdns

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestODOHClientSimple(t *testing.T) {
	d, err := NewODoHClient("test-odoh", "", "https://odoh.cloudflare-dns.com/dns-query", "", DoHClientOptions{})
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	r, err := d.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, r.Answer)
}

// A client packs a copy and leaves the caller's message alone, because packing
// writes the extended rcode into the query's OPT record. The rcode below is
// what makes that write visible: it only changes the record for a value above
// 15, so an ordinary query is written back as it was and the modification goes
// unnoticed until something carries one.
func TestODoHClientLeavesQueryAlone(t *testing.T) {
	kp, err := odoh.CreateDefaultKeyPair()
	require.NoError(t, err)
	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{kp.Config})

	// A proxy nothing listens on: the query is packed and encrypted before
	// anything goes out, which is where a message would be modified.
	d, err := NewODoHClient("test-odoh", "https://127.0.0.1:1/dns-query",
		"https://target.example.com/dns-query", hex.EncodeToString(configs.Marshal()),
		DoHClientOptions{QueryTimeout: time.Second})
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(4096, true)
	q.Rcode = dns.RcodeBadVers
	opt := q.Extra[0].(*dns.OPT)
	ttl := opt.Hdr.Ttl

	_, err = d.Resolve(q, ClientInfo{})
	require.Error(t, err, "the proxy is not listening, so the call has to fail")
	require.Equal(t, ttl, opt.Hdr.Ttl, "packing wrote into the caller's OPT record")
}
