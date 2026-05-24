package rdns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDoQListenerStartStop verifies that Stop() unblocks Start(). This guards
// two bugs: the value-receiver bug (where the listener bound in Start() was
// invisible to Stop()) and the Accept loop spinning on ErrServerClosed after
// the listener is closed. Either one leaves Start() running forever.
func TestDoQListenerStartStop(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getUDPLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)

	stopped := make(chan error, 1)
	go func() { stopped <- s.Start() }()

	// Give the listener a moment to bind and start accepting.
	time.Sleep(500 * time.Millisecond)

	require.NoError(t, s.Stop())

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop; listener is spinning on Accept")
	}
}
