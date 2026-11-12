package rdns

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// hangingAddr returns the address of a TCP listener on which connecting hangs:
// on Linux a full accept queue drops new connection attempts.
func hangingAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	raw, err := ln.(*net.TCPListener).SyscallConn()
	require.NoError(t, err)
	require.NoError(t, raw.Control(func(fd uintptr) { err = syscall.Listen(int(fd), 0) }))
	require.NoError(t, err)
	for range 100 { // fill the queue
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond)
		if err != nil {
			return ln.Addr().String()
		}
		t.Cleanup(func() { conn.Close() })
	}
	t.Fatal("accept queue never filled up")
	return ""
}

// A connection attempt to an upstream that drops packets has to end at the
// connect timeout, not run for as long as the kernel keeps retrying it.
func TestConnectionAttemptTimeout(t *testing.T) {
	dot, err := NewDoTClient("test-hang-dot", "127.0.0.1:853", DoTClientOptions{})
	require.NoError(t, err)
	tcp, err := NewDNSClient("test-hang-tcp", "127.0.0.1:53", "tcp", DNSClientOptions{})
	require.NoError(t, err)
	doh, err := dohTcpTransport(DoHClientOptions{})
	require.NoError(t, err)
	dohLocal, err := dohTcpTransport(DoHClientOptions{LocalAddr: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	require.Equal(t, dohTLSHandshakeTimeout, doh.(*http.Transport).TLSHandshakeTimeout)

	get := func(tr http.RoundTripper) func(string) error {
		return func(addr string) error {
			_, err := (&http.Client{Transport: tr}).Get("https://" + addr)
			return err
		}
	}
	dialers := map[string]func(addr string) error{
		"dot":               func(addr string) error { _, err := dot.pipeline.client.Dial(addr); return err },
		"tcp":               func(addr string) error { _, err := tcp.pipeline.client.Dial(addr); return err },
		"doh":               get(doh),
		"doh-local-address": get(dohLocal),
	}
	addr := hangingAddr(t)
	var wg sync.WaitGroup
	for name, dial := range dialers { // all at once, each takes the full timeout
		wg.Go(func() {
			start := time.Now()
			done := make(chan error, 1)
			go func() { done <- dial(addr) }()
			select {
			case err := <-done:
				var timedOut net.Error
				if !errors.As(err, &timedOut) || !timedOut.Timeout() || time.Since(start) < connectTimeout {
					t.Errorf("%s: want a timeout after %v, got %v after %v", name, connectTimeout, err, time.Since(start))
				}
			case <-time.After(connectTimeout + time.Second):
				t.Errorf("%s: still connecting after the connect timeout", name)
			}
		})
	}
	wg.Wait()
}
