package main

import (
	"errors"
	"sync"
	"testing"
	"testing/synctest"
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
// Start() actually returns, rather than blocking on its result forever. If the
// no-op Stop were not retried, Start would never return and the bubble would
// deadlock, failing the test.
func TestStopNetNSListenerRetriesUntilStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeNetNSListener(1) // first Stop is a no-op, second takes effect

		startErr := make(chan error, 1)
		go func() { startErr <- f.Start() }()

		stopNetNSListener("test", f, startErr)

		if c := f.calls(); c < 2 {
			t.Fatalf("expected Stop() to be retried, got %d call(s)", c)
		}
	})
}

// When Stop() works on the first try the supervisor must not retry needlessly.
func TestStopNetNSListenerStopsImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeNetNSListener(0)

		startErr := make(chan error, 1)
		go func() { startErr <- f.Start() }()

		stopNetNSListener("test", f, startErr)

		if c := f.calls(); c != 1 {
			t.Fatalf("expected exactly 1 Stop() call, got %d", c)
		}
	})
}

// stubWaitNetNSReady replaces waitNetNSReady for the duration of a test.
func stubWaitNetNSReady(t *testing.T, fn func(name string, timeout time.Duration) error) {
	old := waitNetNSReady
	waitNetNSReady = fn
	t.Cleanup(func() { waitNetNSReady = old })
}

// A listener that fails to build while its namespace is present must be retried
// on a timer rather than waiting for the next namespace event.
func TestNetNSSupervisorRetriesBuildFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stubWaitNetNSReady(t, func(string, time.Duration) error { return nil })

		// The counters need a mutex even under synctest: the supervisor's
		// retries are woken by its retry timer rather than by an operation of
		// this goroutine, so there is no happens-before edge between a read
		// here and the write in the next retry.
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
		attemptCount := func() int {
			mu.Lock()
			defer mu.Unlock()
			return attempts
		}

		events := make(chan rdns.NetNSState, 1)
		done := make(chan struct{})
		go func() {
			runNetNSSupervisor("test", "ns", events, build)
			close(done)
		}()

		// Namespace is present, the first build fails: the supervisor must be
		// waiting on the retry timer, not for the next namespace event.
		events <- rdns.NetNSPresent
		synctest.Wait()
		require.Equal(t, 1, attemptCount())

		// First retry fires on the (fake) clock and fails again.
		time.Sleep(netnsRetryInterval)
		synctest.Wait()
		require.Equal(t, 2, attemptCount())

		// Second retry succeeds and starts the listener.
		time.Sleep(netnsRetryInterval)
		synctest.Wait()
		require.Equal(t, 3, attemptCount())
		mu.Lock()
		require.NotNil(t, started, "listener was not started after the build succeeded")
		mu.Unlock()

		// Tear down: namespace goes away (stops the listener), then end the
		// loop. If the supervisor doesn't exit, the bubble deadlocks and
		// synctest fails the test.
		events <- rdns.NetNSAbsent
		close(events)
		<-done
	})
}

// When a namespace appears, the supervisor must wait for it to be fully set up
// (the bind mount "ip netns add" performs after creating the file) before
// building and starting the listener, so the listener never tries to bind into
// the unmounted placeholder.
func TestNetNSSupervisorWaitsForReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ready := make(chan struct{})
		stubWaitNetNSReady(t, func(string, time.Duration) error {
			<-ready
			return nil
		})

		builds := 0
		build := func() (rdns.Listener, error) {
			builds++
			return newFakeNetNSListener(0), nil
		}

		events := make(chan rdns.NetNSState, 1)
		done := make(chan struct{})
		go func() {
			runNetNSSupervisor("test", "ns", events, build)
			close(done)
		}()

		// The namespace appears, but isn't ready yet: once the bubble is idle
		// the supervisor is blocked in waitNetNSReady and no build must have
		// happened.
		events <- rdns.NetNSPresent
		synctest.Wait()
		require.Equal(t, 0, builds, "listener must not be built before the namespace is ready")

		// The namespace becomes ready: the listener must be built and started.
		close(ready)
		synctest.Wait()
		require.Equal(t, 1, builds, "listener was not started after the namespace became ready")

		// Tear down: namespace goes away (stops the listener), then end the
		// loop. If the supervisor doesn't exit, the bubble deadlocks and
		// synctest fails the test.
		events <- rdns.NetNSAbsent
		close(events)
		<-done
	})
}
