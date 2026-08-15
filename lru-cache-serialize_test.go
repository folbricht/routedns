package rdns

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A cache file written before this change must still load, so an upgrade
// doesn't silently discard the cache. This record was produced by the previous
// encoder, which built its output through cacheAnswer.MarshalJSON.
const legacyCacheRecord = `{"Key":{"Question":{"Name":"host.example.com.","Qtype":1,"Qclass":1},"Net":"192.0.2.0","Do":true,"CD":true,"ECSMask":24},"Answer":{"Timestamp":"2026-08-08T12:00:00.123456789Z","Expiry":"2126-08-08T13:00:00.123456789Z","PrefetchEligible":true,"Msg":"khIBAAABAAEAAAAABGhvc3QHZXhhbXBsZQNjb20AAAEAAQRob3N0B2V4YW1wbGUDY29tAAABAAEAAAEsAATAAAIB"}}
`

func TestLRUDeserializeLegacyFormat(t *testing.T) {
	c := newLRUCache(0)
	require.NoError(t, c.deserialize(strings.NewReader(legacyCacheRecord)))
	require.Equal(t, 1, c.size())

	key := lruKey{
		Question: dns.Question{Name: "host.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Net:      "192.0.2.0",
		Do:       true,
		CD:       true,
		ECSMask:  24,
	}
	item := c.find(key)
	require.NotNil(t, item, "the record's key must survive unchanged")
	require.Equal(t, "host.example.com.", item.msg.Question[0].Name)
	require.True(t, item.prefetchEligible)
}

// Pins the exact bytes written for a fully-populated record. The cache file
// has to stay readable by older builds, so any change to field names, order or
// encoding has to be deliberate rather than a side effect of touching the
// structs this is built from.
func TestLRUSerializeFormatStable(t *testing.T) {
	ts, err := time.Parse(time.RFC3339Nano, "2026-08-08T12:00:00.123456789Z")
	require.NoError(t, err)

	msg := new(dns.Msg)
	msg.SetQuestion("host.example.com.", dns.TypeA)
	msg.Id = 4242 // SetQuestion randomises this
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IP{192, 0, 2, 1},
		},
	}

	c := newLRUCache(0)
	c.addKey(lruKey{
		Question: dns.Question{Name: "host.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		Net:      "192.0.2.0",
		Do:       true,
		CD:       true,
		ECSMask:  24,
	}, &cacheAnswer{
		Timestamp:        ts,
		Expiry:           ts.Add(time.Hour),
		PrefetchEligible: true,
		Msg:              msg,
	})

	var buf bytes.Buffer
	require.NoError(t, c.serialize(&buf))

	// Field names and order must match what encoding/json produced for the
	// old cacheItem/cacheAnswer pair.
	require.Equal(t,
		`{"Key":{"Question":{"Name":"host.example.com.","Qtype":1,"Qclass":1},"Net":"192.0.2.0","Do":true,"CD":true,"ECSMask":24},`+
			`"Answer":{"Timestamp":"2026-08-08T12:00:00.123456789Z","Expiry":"2026-08-08T13:00:00.123456789Z","PrefetchEligible":true,`+
			`"Msg":"EJIBAAABAAEAAAAABGhvc3QHZXhhbXBsZQNjb20AAAEAAQRob3N0B2V4YW1wbGUDY29tAAABAAEAAAEsAATAAAIB"}}`+"\n",
		buf.String())
}

// A truncated or corrupt record is skipped rather than taking the whole cache
// file down with it.
func TestLRUDeserializeSkipsBadRecords(t *testing.T) {
	good := `{"Key":{"Question":{"Name":"good.example.com.","Qtype":1,"Qclass":1}},"Answer":{"Timestamp":"2026-08-08T12:00:00Z","Expiry":"2126-08-08T13:00:00Z","Msg":"khIBAAABAAEAAAAABGhvc3QHZXhhbXBsZQNjb20AAAEAAQRob3N0B2V4YW1wbGUDY29tAAABAAEAAAEsAATAAAIB"}}`
	// No name, and an entry whose message isn't valid wire format.
	noName := `{"Key":{"Question":{"Name":"","Qtype":1,"Qclass":1}},"Answer":{"Msg":"AAEC"}}`
	badMsg := `{"Key":{"Question":{"Name":"bad.example.com.","Qtype":1,"Qclass":1}},"Answer":{"Msg":"AAEC"}}`

	c := newLRUCache(0)
	require.NoError(t, c.deserialize(strings.NewReader(noName+"\n"+badMsg+"\n"+good+"\n")))
	require.Equal(t, 1, c.size(), "only the good record should load")
}
