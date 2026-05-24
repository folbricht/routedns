package main

import (
	"errors"
	"sync"
	"testing"
	"time"
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
