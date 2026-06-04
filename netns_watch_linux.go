//go:build linux

package rdns

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// netnsDir is where "ip netns" mounts named network namespaces. It is a var
// so tests can point it at a temporary directory.
var netnsDir = "/var/run/netns"

// netnsPath resolves a namespace reference to a filesystem path: an absolute
// path is used as-is, anything else is looked up under netnsDir.
func netnsPath(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(netnsDir, name)
}

// NetNSState represents whether a Linux network namespace is currently
// present in the filesystem.
type NetNSState int

const (
	NetNSAbsent NetNSState = iota
	NetNSPresent
)

type netnsSubscriber struct {
	name    string
	ch      chan NetNSState
	last    NetNSState
	hasLast bool
}

type netnsWatcher struct {
	mu   sync.Mutex
	fd   int
	subs []*netnsSubscriber
}

var (
	nsWatcherOnce sync.Once
	nsWatcher     *netnsWatcher
	nsWatcherErr  error
)

// SubscribeNetNS returns a channel that receives state changes for the named
// network namespace, plus a cancel function to unsubscribe. name must be a
// namespace name under /var/run/netns, not an absolute path. The current
// state is delivered immediately on subscription; subsequent values reflect
// changes. It fails if /var/run/netns does not exist: the directory is
// created by the first "ip netns add" after boot, so routedns must either be
// started after that or the directory created beforehand (e.g. with
// "ExecStartPre=+mkdir -p /run/netns" in a systemd unit).
func SubscribeNetNS(name string) (<-chan NetNSState, func(), error) {
	nsWatcherOnce.Do(func() {
		nsWatcher, nsWatcherErr = newNetNSWatcher()
	})
	if nsWatcherErr != nil {
		return nil, nil, nsWatcherErr
	}
	ch, cancel := nsWatcher.subscribe(name)
	return ch, cancel, nil
}

func newNetNSWatcher() (*netnsWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	const mask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM
	if _, err := unix.InotifyAddWatch(fd, netnsDir, mask); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("netns directory %s does not exist; create it before starting routedns, or start routedns after the first \"ip netns add\"", netnsDir)
		}
		return nil, fmt.Errorf("failed to watch %s: %w", netnsDir, err)
	}
	w := &netnsWatcher{fd: fd}
	go w.read()
	return w, nil
}

// read pulls events from the inotify fd and dispatches them to subscribers.
func (w *netnsWatcher) read() {
	var buf [4096]byte
	for {
		n, err := unix.Read(w.fd, buf[:])
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			Log.Error("netns watcher: read failed, watcher disabled", "error", err)
			return
		}
		offset := 0
		for offset+unix.SizeofInotifyEvent <= n {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(ev.Len)
			var name string
			if nameLen > 0 {
				start := offset + unix.SizeofInotifyEvent
				nameBytes := buf[start : start+nameLen]
				if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
					nameBytes = nameBytes[:i]
				}
				name = string(nameBytes)
			}
			offset += unix.SizeofInotifyEvent + nameLen

			var state NetNSState
			switch {
			case ev.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
				state = NetNSPresent
			case ev.Mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0:
				state = NetNSAbsent
			default:
				continue
			}
			if name == "" {
				continue
			}
			w.dispatch(name, state)
		}
	}
}

func (w *netnsWatcher) dispatch(name string, state NetNSState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.subs {
		if s.name == name {
			w.notifyLocked(s, state)
		}
	}
}

func (w *netnsWatcher) subscribe(name string) (<-chan NetNSState, func()) {
	s := &netnsSubscriber{name: name, ch: make(chan NetNSState, 16)}
	state := currentNetNSState(name)

	w.mu.Lock()
	w.subs = append(w.subs, s)
	// Deliver the current state immediately so the caller learns the
	// namespace is absent even when /var/run/netns doesn't exist yet and the
	// inotify watch hasn't been installed.
	w.notifyLocked(s, state)
	w.mu.Unlock()

	cancel := func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		for i, ss := range w.subs {
			if ss == s {
				w.subs = append(w.subs[:i], w.subs[i+1:]...)
				return
			}
		}
	}
	return s.ch, cancel
}

// netnsReadyRecheckInterval is how often WaitNetNSReady re-checks the
// namespace path. The bind mount completing fires no inotify event, and the
// event-driven alternative — poll(POLLPRI) on /proc/self/mountinfo — isn't
// reliable: when routedns runs in its own mount namespace (e.g. sandboxed by
// systemd's DynamicUser), a namespace mount propagating in from the host
// doesn't wake mountinfo pollers on all kernels, and deletion of the
// namespace file changes no mount state at all. So a short fixed interval is
// used instead; it bounds both the listener-start latency after
// "ip netns add" and the detection of a namespace deleted mid-wait.
const netnsReadyRecheckInterval = 10 * time.Millisecond

// WaitNetNSReady blocks until the named network namespace is fully set up and
// usable, the namespace file disappears, or the timeout expires. name is
// either a namespace name under /var/run/netns or an absolute path.
//
// "ip netns add" is not atomic: it first creates a placeholder file (which is
// what fires the inotify CREATE event the watcher reacts to), then bind-mounts
// the actual namespace onto it. In the gap between the two, opening the path
// fails (EACCES on the mode-000 placeholder for a non-root process, EINVAL
// from setns otherwise). So this waits by checking whether the path is an
// nsfs mount (statfs) every netnsReadyRecheckInterval.
func WaitNetNSReady(name string, timeout time.Duration) error {
	path := netnsPath(name)

	deadline := time.Now().Add(timeout)
	for {
		var st unix.Statfs_t
		err := unix.Statfs(path, &st)
		switch {
		case err == nil && st.Type == unix.NSFS_MAGIC:
			return nil // the real namespace is mounted over the placeholder
		case errors.Is(err, unix.ENOENT):
			return fmt.Errorf("netns %q does not exist", name)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("timed out waiting for netns %q to be mounted", name)
		}
		time.Sleep(min(remaining, netnsReadyRecheckInterval))
	}
}

// currentNetNSState reports whether the named namespace file currently exists.
func currentNetNSState(name string) NetNSState {
	if _, err := os.Stat(netnsPath(name)); err == nil {
		return NetNSPresent
	}
	return NetNSAbsent
}

// notifyLocked delivers a state change to a subscriber, skipping it if the
// subscriber's last delivered state is identical. The send is non-blocking; if
// the channel buffer is full the state is dropped without being recorded, so
// it is retried on the next event rather than being deduplicated away. Must be
// called with w.mu held.
func (w *netnsWatcher) notifyLocked(s *netnsSubscriber, state NetNSState) {
	if s.hasLast && s.last == state {
		return
	}
	select {
	case s.ch <- state:
		s.last = state
		s.hasLast = true
	default:
	}
}
