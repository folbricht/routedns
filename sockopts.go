package rdns

// SocketOptions contains Linux-specific socket options for controlling
// packet routing and interface binding. These options map to the SO_MARK
// and SO_BINDTODEVICE socket options.
type SocketOptions struct {
	// Firewall mark (SO_MARK) to set on the socket. 0 means unset.
	FWMark int

	// Network interface to bind the socket to (SO_BINDTODEVICE). Empty means unset.
	BindInterface string
}

// active returns true if any socket options are configured.
func (s SocketOptions) active() bool {
	return s.FWMark > 0 || s.BindInterface != ""
}
