package rdns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockNotifier struct {
	mock.Mock
}

// Used to mock  a NotifyStartedFunc
func (m *mockNotifier) NotifyStarted() {
	m.Called()
}

// NotifyStartedFunc is invoked once the ODoH listener is up, which is used by
// the router to wait for all listeners before starting to serve.
func testNotifyStartedFunc(t *testing.T, makeListener func(*testing.T, func()) Listener) {
	started := make(chan struct{})
	notifier := &mockNotifier{}
	notifier.On("NotifyStarted").Once().Return().Run(func(mock.Arguments) {
		close(started)
	})

	l := makeListener(t, notifier.NotifyStarted)

	go l.Start()
	defer l.Stop()
	select {
	case <-started:
	case <-time.After(1 * time.Minute):
		t.Fatal("timeout")
	}

	mock.AssertExpectationsForObjects(t, notifier)
}

func TestDNSListenerNotifyStartedFunc(t *testing.T) {
	testNotifyStartedFunc(t,
		func(t *testing.T, f func()) Listener {
			addr, err := getLnAddress()
			require.NoError(t, err)

			return NewDNSListener("test-dns-notify-started-func", addr, "udp",
				ListenOptions{NotifyStartedFunc: f},
				new(TestResolver))
		})
}

func TestAdminListenerNotifyStartedFunc(t *testing.T) {
	testNotifyStartedFunc(t,
		func(t *testing.T, f func()) Listener {
			addr, err := getLnAddress()
			require.NoError(t, err)

			tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
			require.NoError(t, err)

			l, err := NewAdminListener("test-admin-notify-started-func", addr, AdminListenerOptions{
				ListenOptions: ListenOptions{NotifyStartedFunc: f},
				TLSConfig:     tlsServerConfig,
				Transport:     "tcp",
			})
			require.NoError(t, err)
			return l
		})
}

func TestDoHListenerNotifyStartedFunc(t *testing.T) {
	testNotifyStartedFunc(t,
		func(t *testing.T, f func()) Listener {
			addr, err := getLnAddress()
			require.NoError(t, err)

			tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
			require.NoError(t, err)

			l, err := NewDoHListener("test-doh-notify-started-func", addr, DoHListenerOptions{
				ListenOptions: ListenOptions{NotifyStartedFunc: f},
				TLSConfig:     tlsServerConfig,
			}, new(TestResolver))
			require.NoError(t, err)
			return l
		})
}

func TestDoQListenerNotifyStartedFunc(t *testing.T) {
	testNotifyStartedFunc(t,
		func(t *testing.T, f func()) Listener {
			addr, err := getLnAddress()
			require.NoError(t, err)

			tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
			require.NoError(t, err)

			return NewQUICListener("test-doq-notify-started-func", addr, DoQListenerOptions{
				ListenOptions: ListenOptions{NotifyStartedFunc: f},
				TLSConfig:     tlsServerConfig,
			}, new(TestResolver))
		})
}

func TestDoTListenerNotifyStartedFunc(t *testing.T) {
	testNotifyStartedFunc(t,
		func(t *testing.T, f func()) Listener {
			addr, err := getLnAddress()
			require.NoError(t, err)

			tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
			require.NoError(t, err)

			return NewDoTListener("test-dot-notify-started-func", addr, "tcp", DoTListenerOptions{
				ListenOptions: ListenOptions{NotifyStartedFunc: f},
				TLSConfig:     tlsServerConfig,
			}, new(TestResolver))
		})
}

func TestDTLSListenerNotifyStartedFunc(t *testing.T) {
	testNotifyStartedFunc(t,
		func(t *testing.T, f func()) Listener {
			addr, err := getLnAddress()
			require.NoError(t, err)

			dtlsConfig, err := DTLSServerConfig("", "testdata/server.crt", "testdata/server.key", false, nil)
			require.NoError(t, err)

			return NewDTLSListener("test-dtls-notify-started-func", addr, DTLSListenerOptions{
				ListenOptions: ListenOptions{NotifyStartedFunc: f},
				DTLSConfig:    dtlsConfig,
			}, new(TestResolver))
		})
}

func TestODoHListenerNotifyStartedFunc(t *testing.T) {
	testNotifyStartedFunc(t,
		func(t *testing.T, f func()) Listener {
			addr, err := getLnAddress()
			require.NoError(t, err)

			tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
			require.NoError(t, err)

			l, err := NewODoHListener("test-odoh-notify-started-func", addr, ODoHListenerOptions{
				ListenOptions: ListenOptions{NotifyStartedFunc: f},
				TLSConfig:     tlsServerConfig,
			}, new(TestResolver))
			require.NoError(t, err)
			return l
		})
}
