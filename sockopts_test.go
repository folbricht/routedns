package rdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSocketOptionsActive(t *testing.T) {
	tests := []struct {
		name   string
		opts   SocketOptions
		active bool
	}{
		{"empty", SocketOptions{}, false},
		{"fwmark only", SocketOptions{FWMark: 11}, true},
		{"bind-if only", SocketOptions{BindInterface: "eth0"}, true},
		{"both", SocketOptions{FWMark: 11, BindInterface: "eth0"}, true},
		{"zero fwmark", SocketOptions{FWMark: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.active, tt.opts.active())
		})
	}
}

func TestSocketOptionsDialerControlNil(t *testing.T) {
	opts := SocketOptions{}
	require.Nil(t, opts.dialerControl(), "expected nil control function for empty socket options")
}
