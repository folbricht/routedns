package rdns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultPort(t *testing.T) {
	tests := []struct {
		address     string
		defaultPort string
		expected    string
	}{
		{"", DoTPort, ":853"},
		{"localhost", DoTPort, "localhost:853"},
		{"localhost:123", DoTPort, "localhost:123"},
		{"1.2.3.4", DoTPort, "1.2.3.4:853"},
		{"1.2.3.4:123", DoTPort, "1.2.3.4:123"},
		{"https://localhost", DoHPort, "https://localhost:443"},
		{"https://localhost:123", DoHPort, "https://localhost:123"},
		{"https://localhost:123/path", DoHPort, "https://localhost:123/path"},
		{"https://localhost/dns-query{?dns}", DoHPort, "https://localhost:443/dns-query{?dns}"},
		{"https://1.1.1.1:443/dns-query{?dns}", DoHPort, "https://1.1.1.1:443/dns-query{?dns}"},

		// Invalid endpoints should ideally not be changed
		{"localhost:", DoTPort, "localhost:"},
		{"localhost::123", DoTPort, "localhost::123"},
		{"127.0.0.1:", DoTPort, "127.0.0.1:"},
		{"127.0.0.1::123", DoTPort, "127.0.0.1::123"},
	}
	for _, test := range tests {
		out := AddressWithDefault(test.address, test.defaultPort)
		require.Equal(t, test.expected, out)
	}
}
