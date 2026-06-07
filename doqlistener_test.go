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
		require.FailNow(t, "Start did not return after Stop; listener is spinning on Accept")
	}
}

// TestDoQListenerStopRaceDuringStart calls Stop() concurrently with Start()
// binding the socket (the scenario the netns supervisor creates). It must be
// race-free under -race (s.ln is written by Start and read by Stop) and Start()
// must return. No queries are sent, so TestResolver is not touched.
func TestDoQListenerStopRaceDuringStart(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getUDPLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	s := NewQUICListener("test-doq", addr, DoQListenerOptions{TLSConfig: tlsServerConfig}, upstream)

	stopped := make(chan error, 1)
	go func() { stopped <- s.Start() }()

	// Hammer Stop() (racing Start's bind) and retry until Start returns; Stop
	// is a no-op until the listener is published.
	deadline := time.After(5 * time.Second)
	for {
		_ = s.Stop()
		select {
		case err := <-stopped:
			require.NoError(t, err)
			return
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			require.FailNow(t, "Start did not return while Stop was retried")
		}
	}
}
