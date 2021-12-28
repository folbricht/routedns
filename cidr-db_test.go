package rdns

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCidrDB(t *testing.T) {
	loader := NewStaticLoader([]string{
		"127.0.0.0/24",
		"1.2.0.0/16",
		"2a03:2880:f101:83::0/64",
	})
	db, err := NewCidrDB("testlist", loader)
	require.NoError(t, err)

	tests := []struct {
		ip    net.IP
		match bool
	}{
		{ip: net.ParseIP("127.0.0.1"), match: true},
		{ip: net.ParseIP("1.2.0.0"), match: true},
		{ip: net.ParseIP("192.168.1.1"), match: false},
		{ip: net.ParseIP("2a03:2880:f101:83:1:1:1:1"), match: true},
		{ip: net.ParseIP("::1"), match: false},
	}

	for _, test := range tests {
		_, ok := db.Match(test.ip)
		require.Equal(t, test.match, ok)
	}

}
