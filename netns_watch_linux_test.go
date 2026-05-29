//go:build linux

package rdns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testNonexistentNS = "rdns-test-nonexistent-namespace"

// Subscribing must deliver the current state immediately, without waiting for
// the inotify watch to be installed. This is the case that previously logged
// nothing at startup when /var/run/netns did not exist yet: the watch never
// became active, so no initial state was ever delivered.
func TestNetNSWatcherSubscribeDeliversInitialState(t *testing.T) {
	w := &netnsWatcher{} // no read/ensureWatch goroutines started

	ch, cancel := w.subscribe(testNonexistentNS)
	defer cancel()

	select {
	case state := <-ch:
		require.Equal(t, NetNSAbsent, state)
	case <-time.After(time.Second):
		t.Fatal("expected initial state on subscribe, got none")
	}
}

// A re-sync or repeated event with an unchanged state must not be delivered
// again, so the supervisor doesn't log a duplicate "waiting" warning.
func TestNetNSWatcherDeduplicatesState(t *testing.T) {
	w := &netnsWatcher{}

	ch, cancel := w.subscribe(testNonexistentNS)
	defer cancel()

	// Drain the initial Absent.
	require.Equal(t, NetNSAbsent, <-ch)

	// A duplicate Absent (e.g. ensureWatch's re-sync) must be deduplicated.
	w.dispatch(testNonexistentNS, NetNSAbsent)
	select {
	case <-ch:
		t.Fatal("duplicate Absent should have been deduplicated")
	case <-time.After(100 * time.Millisecond):
	}

	// A genuine change must be delivered.
	w.dispatch(testNonexistentNS, NetNSPresent)
	select {
	case state := <-ch:
		require.Equal(t, NetNSPresent, state)
	case <-time.After(time.Second):
		t.Fatal("expected NetNSPresent to be delivered")
	}
}
