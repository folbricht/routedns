//go:build linux

package rdns

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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

// The watcher must become active promptly when the netns directory itself is
// created after startup. After a reboot, /var/run/netns doesn't exist until
// the first "ip netns add" creates it, and a namespace created moments later
// must still be picked up immediately — not after a polling interval.
func TestNetNSWatcherDetectsDirCreation(t *testing.T) {
	oldDir := netnsDir
	netnsDir = filepath.Join(t.TempDir(), "netns")
	defer func() { netnsDir = oldDir }()

	w, err := newNetNSWatcher()
	require.NoError(t, err)

	ch, cancel := w.subscribe("testns")
	defer cancel()

	// Initial state: directory doesn't exist, namespace is absent.
	require.Equal(t, NetNSAbsent, <-ch)

	// Create the directory and a namespace file in it, like the first
	// "ip netns add" after boot does.
	require.NoError(t, os.Mkdir(netnsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(netnsDir, "testns"), nil, 0o000))

	// Present must be delivered well within the old 5s polling interval.
	select {
	case state := <-ch:
		require.Equal(t, NetNSPresent, state)
	case <-time.After(2 * time.Second):
		t.Fatal("namespace creation not detected after netns directory appeared")
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

// A path that is already an nsfs mount must be reported ready immediately.
// /proc/self/ns/net is nsfs without requiring any privileges or mounts.
func TestWaitNetNSReadyImmediate(t *testing.T) {
	start := time.Now()
	err := WaitNetNSReady("/proc/self/ns/net", 5*time.Second)
	require.NoError(t, err)
	require.Less(t, time.Since(start), time.Second, "ready namespace should be detected without waiting")
}

// A namespace that doesn't exist must fail immediately, not burn the timeout,
// so the supervisor reacts quickly when a namespace is deleted right after
// being created.
func TestWaitNetNSReadyNonexistent(t *testing.T) {
	start := time.Now()
	err := WaitNetNSReady(testNonexistentNS, 5*time.Second)
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second, "missing namespace should fail without waiting")
}

// A file that exists but never becomes a namespace mount (like the placeholder
// "ip netns add" creates first, or a stray file) must time out rather than
// hang forever.
func TestWaitNetNSReadyTimeout(t *testing.T) {
	placeholder := filepath.Join(t.TempDir(), "ns")
	require.NoError(t, os.WriteFile(placeholder, nil, 0o000))

	start := time.Now()
	err := WaitNetNSReady(placeholder, 100*time.Millisecond)
	require.Error(t, err)
	require.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond, "should have waited for the timeout")
}

// The poll on /proc/self/mountinfo must wake up when the namespace is
// bind-mounted over the placeholder, completing the wait without any retry
// interval. This is the exact sequence "ip netns add" performs. Requires root.
func TestWaitNetNSReadyOnMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to bind-mount a namespace")
	}

	placeholder := filepath.Join(t.TempDir(), "ns")
	require.NoError(t, os.WriteFile(placeholder, nil, 0o000))

	// Bind-mount the real namespace over the placeholder after a delay,
	// mirroring the non-atomic behavior of "ip netns add".
	errC := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		errC <- unix.Mount("/proc/self/ns/net", placeholder, "none", unix.MS_BIND, "")
	}()
	defer unix.Unmount(placeholder, unix.MNT_DETACH) //nolint:errcheck

	start := time.Now()
	err := WaitNetNSReady(placeholder, 5*time.Second)
	require.NoError(t, <-errC, "bind mount failed")
	require.NoError(t, err)
	elapsed := time.Since(start)
	require.GreaterOrEqual(t, elapsed, 50*time.Millisecond, "must not report ready before the mount")
	require.Less(t, elapsed, time.Second, "must wake up promptly when the mount lands")
}
