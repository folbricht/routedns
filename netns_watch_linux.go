//go:build linux

package rdns

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const netnsDir = "/var/run/netns"

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
// network namespace, plus a cancel function to unsubscribe. The current state
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
	w := &netnsWatcher{fd: fd}
	go w.read()
	go w.ensureWatch()
	return w, nil
}

// ensureWatch installs the inotify watch on the netns directory, retrying
// with a slow backoff if the directory does not yet exist.
func (w *netnsWatcher) ensureWatch() {
	const mask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM
	for {
		if _, err := unix.InotifyAddWatch(w.fd, netnsDir, mask); err == nil {
			// Re-sync every subscriber: events that occurred before the
			// watch was installed (e.g. while the directory didn't exist
			// yet) were missed. notifyLocked drops any state that hasn't
			// actually changed, so this won't re-warn for an unchanged
			// namespace.
			w.mu.Lock()
			for _, s := range w.subs {
				w.notifyLocked(s, currentNetNSState(s.name))
			}
			w.mu.Unlock()
			return
		} else if !errors.Is(err, unix.ENOENT) {
			Log.Warn("netns watcher: inotify_add_watch failed", "dir", netnsDir, "error", err)
		}
		time.Sleep(5 * time.Second)
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

func currentNetNSState(name string) NetNSState {
	if _, err := os.Stat(filepath.Join(netnsDir, name)); err == nil {
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
