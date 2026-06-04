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

// Subscribing must deliver the current state immediately, so the supervisor
// logs "waiting" right away for a namespace that doesn't exist yet.
func TestNetNSWatcherSubscribeDeliversInitialState(t *testing.T) {
	w := &netnsWatcher{} // no watch installed, no read goroutine started

	ch, cancel := w.subscribe(testNonexistentNS)
	defer cancel()

	select {
	case state := <-ch:
		require.Equal(t, NetNSAbsent, state)
	case <-time.After(time.Second):
		require.Fail(t, "expected initial state on subscribe, got none")
	}
}

// When the netns directory doesn't exist, the watcher must fail with a clear
// error rather than watching or polling for the directory's creation. The
// directory is created by the first "ip netns add" after boot; starting
// routedns before that is a setup error the user has to resolve.
func TestNetNSWatcherMissingDir(t *testing.T) {
	old := netnsDir
	netnsDir = filepath.Join(t.TempDir(), "netns") // doesn't exist
	t.Cleanup(func() { netnsDir = old })

	_, err := newNetNSWatcher()
	require.ErrorContains(t, err, "does not exist")
}

// A namespace file created after the watcher starts must be detected via the
// inotify event, not a polling interval.
func TestNetNSWatcherDetectsCreation(t *testing.T) {
	old := netnsDir
	netnsDir = t.TempDir()
	t.Cleanup(func() { netnsDir = old })

	w, err := newNetNSWatcher()
	require.NoError(t, err)

	ch, cancel := w.subscribe("testns")
	defer cancel()

	// Initial state: namespace file doesn't exist yet.
	require.Equal(t, NetNSAbsent, <-ch)

	// Create the namespace file like "ip netns add" does.
	require.NoError(t, os.WriteFile(filepath.Join(netnsDir, "testns"), nil, 0o000))

	select {
	case state := <-ch:
		require.Equal(t, NetNSPresent, state)
	case <-time.After(2 * time.Second):
		require.Fail(t, "namespace creation not detected")
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

	// A duplicate Absent (e.g. a repeated event) must be deduplicated.
	w.dispatch(testNonexistentNS, NetNSAbsent)
	select {
	case <-ch:
		require.Fail(t, "duplicate Absent should have been deduplicated")
	case <-time.After(100 * time.Millisecond):
	}

	// A genuine change must be delivered.
	w.dispatch(testNonexistentNS, NetNSPresent)
	select {
	case state := <-ch:
		require.Equal(t, NetNSPresent, state)
	case <-time.After(time.Second):
		require.Fail(t, "expected NetNSPresent to be delivered")
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

// A namespace file deleted while waiting must be detected within the re-check
// interval, not only when the timeout expires. This is what happens when a
// "namespace creator" service gives up and cleans up its namespace while the
// wait is in progress.
func TestWaitNetNSReadyDetectsDeletionWhileWaiting(t *testing.T) {
	placeholder := filepath.Join(t.TempDir(), "ns")
	require.NoError(t, os.WriteFile(placeholder, nil, 0o000))

	go func() {
		time.Sleep(100 * time.Millisecond)
		os.Remove(placeholder)
	}()

	start := time.Now()
	err := WaitNetNSReady(placeholder, 5*time.Second)
	elapsed := time.Since(start)
	require.Error(t, err)
	require.Less(t, elapsed, time.Second, "deletion should be detected by the bounded re-check, not the timeout")
}

// The wait must complete promptly once the namespace is bind-mounted over the
// placeholder. This is the exact sequence "ip netns add" performs. Requires
// root.
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
