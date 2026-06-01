package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/stretchr/testify/require"
)

// fakeNetNSListener simulates a listener whose Stop() is a no-op for its first
// failFirstN calls, mirroring the real race the supervisor must tolerate: a
// dns.Server's Shutdown returns "server not started" before it begins serving,
// and a freshly-built DoQ listener isn't bound yet. Start() blocks until an
// effective Stop() releases it.
type fakeNetNSListener struct {
	mu         sync.Mutex
	stopCalls  int
	failFirstN int
	stop       chan struct{}
}

func newFakeNetNSListener(failFirstN int) *fakeNetNSListener {
	return &fakeNetNSListener{failFirstN: failFirstN, stop: make(chan struct{})}
}

func (f *fakeNetNSListener) Start() error {
	<-f.stop
	return nil
}

func (f *fakeNetNSListener) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	if f.stopCalls <= f.failFirstN {
		return errors.New("server not started")
	}
	select {
	case <-f.stop:
	default:
		close(f.stop)
	}
	return nil
}

func (f *fakeNetNSListener) String() string { return "fake" }

func (f *fakeNetNSListener) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCalls
}

// A Stop() that is a no-op until the listener is serving must be retried until
// Start() actually returns, rather than blocking on its result forever.
func TestStopNetNSListenerRetriesUntilStopped(t *testing.T) {
	f := newFakeNetNSListener(1) // first Stop is a no-op, second takes effect

	startErr := make(chan error, 1)
	go func() { startErr <- f.Start() }()

	done := make(chan struct{})
	go func() {
		stopNetNSListener("test", f, startErr)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stopNetNSListener deadlocked: Stop was a no-op and Start never returned")
	}
	if c := f.calls(); c < 2 {
		t.Fatalf("expected Stop() to be retried, got %d call(s)", c)
	}
}

// When Stop() works on the first try the supervisor must not retry needlessly.
func TestStopNetNSListenerStopsImmediately(t *testing.T) {
	f := newFakeNetNSListener(0)

	startErr := make(chan error, 1)
	go func() { startErr <- f.Start() }()

	done := make(chan struct{})
	go func() {
		stopNetNSListener("test", f, startErr)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopNetNSListener did not return")
	}
	if c := f.calls(); c != 1 {
		t.Fatalf("expected exactly 1 Stop() call, got %d", c)
	}
}

// flakyStartListener fails its first failStarts Start() calls (mirroring the
// EACCES seen while "ip netns add" has only created the mode-000 placeholder
// but not yet bind-mounted the namespace), then blocks like a healthy listener.
type flakyStartListener struct {
	mu         sync.Mutex
	startCalls int
	failStarts int
	stop       chan struct{}
}

func (f *flakyStartListener) Start() error {
	f.mu.Lock()
	f.startCalls++
	n := f.startCalls
	f.mu.Unlock()
	if n <= f.failStarts {
		return errors.New("failed to open target netns \"ns\": permission denied")
	}
	<-f.stop
	return nil
}

func (f *flakyStartListener) Stop() error {
	select {
	case <-f.stop:
	default:
		close(f.stop)
	}
	return nil
}

func (f *flakyStartListener) String() string { return "flaky" }

func (f *flakyStartListener) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls
}

// When a freshly-created namespace isn't mounted yet, the first start fails;
// the supervisor must retry on the short initial interval and bind successfully
// once the namespace becomes usable, rather than waiting a full second.
func TestNetNSSupervisorRetriesStartFailureFast(t *testing.T) {
	oldMax, oldInit := netnsRetryInterval, netnsInitialRetryInterval
	netnsRetryInterval = 50 * time.Millisecond
	netnsInitialRetryInterval = 2 * time.Millisecond
	defer func() { netnsRetryInterval, netnsInitialRetryInterval = oldMax, oldInit }()

	ln := &flakyStartListener{failStarts: 2, stop: make(chan struct{})}
	build := func() (rdns.Listener, error) { return ln, nil }

	events := make(chan rdns.NetNSState, 1)
	done := make(chan struct{})
	go func() {
		runNetNSSupervisor("test", "ns", events, build)
		close(done)
	}()

	events <- rdns.NetNSPresent
	// Two fast retries (2ms + 4ms) plus scheduling overhead must land well
	// under the 50ms cap; require completion inside a window far shorter than
	// three full-interval retries would take.
	require.Eventually(t, func() bool {
		return ln.calls() >= 3
	}, 200*time.Millisecond, 1*time.Millisecond, "start was not retried quickly enough")

	events <- rdns.NetNSAbsent
	close(events)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not exit")
	}
}

// A listener that fails to build while its namespace is present must be retried
// on a timer rather than waiting for the next namespace event.
func TestNetNSSupervisorRetriesBuildFailure(t *testing.T) {
	oldMax, oldInit := netnsRetryInterval, netnsInitialRetryInterval
	netnsRetryInterval = 10 * time.Millisecond
	netnsInitialRetryInterval = 2 * time.Millisecond
	defer func() { netnsRetryInterval, netnsInitialRetryInterval = oldMax, oldInit }()

	var (
		mu       sync.Mutex
		attempts int
		started  *fakeNetNSListener
	)
	build := func() (rdns.Listener, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return nil, errors.New("address already in use")
		}
		started = newFakeNetNSListener(0)
		return started, nil
	}

	events := make(chan rdns.NetNSState, 1)
	done := make(chan struct{})
	go func() {
		runNetNSSupervisor("test", "ns", events, build)
		close(done)
	}()

	// Namespace is present but the first two builds fail; the supervisor must
	// keep retrying on the timer until the third build succeeds.
	events <- rdns.NetNSPresent
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return attempts >= 3 && started != nil
	}, 2*time.Second, 5*time.Millisecond, "build was not retried until it succeeded")

	// Tear down: namespace goes away (stops the listener), then end the loop.
	events <- rdns.NetNSAbsent
	close(events)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not exit")
	}
}
