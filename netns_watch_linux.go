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
	dir  string // directory holding the namespace files, netnsDir
	subs []*netnsSubscriber
}

var (
	nsWatcherOnce sync.Once
	nsWatcher     *netnsWatcher
	nsWatcherErr  error
)

// SubscribeNetNS returns a channel that receives state changes for the named
// network namespace, plus a cancel function to unsubscribe. name must be a
// namespace name under /var/run/netns, not an absolute path. The current state
// is delivered immediately on subscription, even if /var/run/netns does not
// exist yet; subsequent values reflect changes.
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
	w := &netnsWatcher{fd: fd, dir: netnsDir}
	go w.read()
	go w.ensureWatch()
	return w, nil
}

// ensureWatch installs the inotify watch on the netns directory. The directory
// itself is created by the first "ip netns add" after boot, so when it doesn't
// exist yet, its creation is awaited via an inotify watch on the parent
// directory rather than by polling.
func (w *netnsWatcher) ensureWatch() {
	const mask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM
	for {
		_, err := unix.InotifyAddWatch(w.fd, w.dir, mask)
		if err == nil {
			// Re-sync every subscriber: events that occurred before the
			// watch was installed (e.g. while the directory didn't exist
			// yet) were missed. notifyLocked drops any state that hasn't
			// actually changed, so this won't re-warn for an unchanged
			// namespace.
			w.mu.Lock()
			for _, s := range w.subs {
				w.notifyLocked(s, w.currentState(s.name))
			}
			w.mu.Unlock()
			return
		}
		if errors.Is(err, unix.ENOENT) {
			waitForDir(w.dir)
			continue
		}
		Log.Warn("netns watcher: inotify_add_watch failed", "dir", w.dir, "error", err)
		time.Sleep(5 * time.Second)
	}
}

// waitForDir blocks until dir exists, watching its parent directory with a
// dedicated inotify instance so the wait is event-driven. If the parent can't
// be watched, it falls back to polling slowly.
func waitForDir(dir string) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err == nil {
		defer unix.Close(fd)
		_, err = unix.InotifyAddWatch(fd, filepath.Dir(dir), unix.IN_CREATE|unix.IN_MOVED_TO)
	}
	if err != nil {
		Log.Warn("netns watcher: can't watch for netns directory creation, polling", "dir", dir, "error", err)
		for {
			if _, err := os.Stat(dir); err == nil {
				return
			}
			time.Sleep(5 * time.Second)
		}
	}
	// Stat before each read: the directory may have been created before the
	// parent watch became active, and an event arriving between the stat and
	// the read just makes the read return immediately.
	buf := make([]byte, 4096)
	for {
		if _, err := os.Stat(dir); err == nil {
			return
		}
		if _, err := unix.Read(fd, buf); err != nil && !errors.Is(err, unix.EINTR) {
			Log.Warn("netns watcher: parent watch read failed, polling", "dir", dir, "error", err)
			time.Sleep(5 * time.Second)
		}
	}
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
	state := w.currentState(name)

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

// WaitNetNSReady blocks until the named network namespace is fully set up and
// usable, the namespace file disappears, or the timeout expires. name is
// either a namespace name under /var/run/netns or an absolute path.
//
// "ip netns add" is not atomic: it first creates a placeholder file (which is
// what fires the inotify CREATE event the watcher reacts to), then bind-mounts
// the actual namespace onto it. In the gap between the two, opening the path
// fails (EACCES on the mode-000 placeholder for a non-root process, EINVAL
// from setns otherwise). The bind mount completing fires no inotify event, but
// it does change the mount table, and the kernel signals POLLPRI on
// /proc/self/mountinfo whenever that happens. So this waits by checking
// whether the path is an nsfs mount (statfs) and sleeping on a mountinfo poll
// between checks — entirely event-driven, no retry intervals.
func WaitNetNSReady(name string, timeout time.Duration) error {
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(netnsDir, name)
	}

	// The poll baseline (mount-table generation counter) is established when
	// the file is opened, so a mount landing any time after this open is
	// guaranteed to wake the poll below. No reads or parsing are needed.
	mounts, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("failed to open mountinfo: %w", err)
	}
	defer mounts.Close()

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
		ms := int(remaining.Milliseconds())
		if ms < 1 {
			ms = 1
		}
		pfds := []unix.PollFd{{Fd: int32(mounts.Fd()), Events: unix.POLLPRI}}
		if _, err := unix.Poll(pfds, ms); err != nil && !errors.Is(err, unix.EINTR) {
			return fmt.Errorf("failed to poll mountinfo: %w", err)
		}
	}
}

// currentState reports whether the named namespace file currently exists.
func (w *netnsWatcher) currentState(name string) NetNSState {
	dir := w.dir
	if dir == "" {
		dir = netnsDir
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
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
