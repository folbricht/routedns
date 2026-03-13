package rdns

import "testing"

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
			if got := tt.opts.active(); got != tt.active {
				t.Errorf("SocketOptions.active() = %v, want %v", got, tt.active)
			}
		})
	}
}

func TestSocketOptionsDialerControlNil(t *testing.T) {
	// No options set should return nil control function
	opts := SocketOptions{}
	if ctrl := opts.dialerControl(); ctrl != nil {
		t.Error("expected nil control function for empty socket options")
	}
}
