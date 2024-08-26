package rdns

import (
	"encoding/hex"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestMACParse(t *testing.T) {
	var tests = []struct {
		input string
		out   []byte
	}{
		{
			input: "01:23:45:ab:cd:ef",
			out:   []byte{0x01, 0x23, 0x45, 0xab, 0xcd, 0xef},
		},
		{
			input: "01:23:45:AB:CD:EF",
			out:   []byte{0x01, 0x23, 0x45, 0xab, 0xcd, 0xef},
		},
	}
	for _, test := range tests {
		out, err := parseMAC(test.input)
		require.NoError(t, err)
		require.Equal(t, test.out, out)
	}
}

func TestMACParseFail(t *testing.T) {
	var tests = []string{
		"",
		"01:23:45:ab:cd:ef:ab",
		"01:2345:ab:cd:ef:",
		"012345abcdef",
		"012345abcdef:::::",
		":::::012345abcdef",
	}
	for _, input := range tests {
		_, err := parseMAC(input)
		require.Errorf(t, err, "value %q", input)
	}
}

func TestMACDB(t *testing.T) {
	loader := NewStaticLoader([]string{
		"# some comment",
		"              ",
		"01:23:45:ab:cd:ef",
		"01:01:01:ff:ff:ff",
	})

	m, err := NewMACDB("testlist", loader)
	require.NoError(t, err)

	tests := []struct {
		mac   []byte
		match bool
	}{
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, false},
		{[]byte{0x01, 0x23, 0x45, 0xab, 0xcd, 0xef}, true},
	}
	for _, test := range tests {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		e := new(dns.EDNS0_LOCAL)
		e.Code = 65001
		e.Data = test.mac
		msg.SetEdns0(4096, false)
		edns0 := msg.IsEdns0()
		edns0.Option = append(edns0.Option, e)

		_, _, _, ok := m.Match(msg)
		require.Equal(t, test.match, ok, "value: %s", hex.EncodeToString(test.mac))
	}
}
