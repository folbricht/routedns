package rdns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAdminListenerStopBeforeStart verifies Stop() is a no-op rather than a
// nil-panic when called before Start() has assigned the server, mirroring the
// netns supervisor stopping a listener whose namespace flapped before it bound.
func TestAdminListenerStopBeforeStart(t *testing.T) {
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	for _, transport := range []string{"tcp", "quic"} {
		t.Run(transport, func(t *testing.T) {
			s, err := NewAdminListener("test-admin", "127.0.0.1:0", AdminListenerOptions{TLSConfig: tlsServerConfig, Transport: transport})
			require.NoError(t, err)
			require.NotPanics(t, func() {
				require.NoError(t, s.Stop())
			})
		})
	}
}
