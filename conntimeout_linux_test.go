package rdns

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// hangingAddr returns the address of a TCP listener on which connecting hangs:
// on Linux a full accept queue drops new connection attempts.
func hangingAddr(t *testing.T) string {
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

// A connection attempt to an upstream that drops packets has to end with the
// query timeout, not run for as long as the kernel keeps retrying it.
func TestConnectionAttemptTimeout(t *testing.T) {
	const timeout = 300 * time.Millisecond
	dot, err := NewDoTClient("test-hang-dot", "127.0.0.1:853", DoTClientOptions{QueryTimeout: timeout})
	require.NoError(t, err)
	doh, err := dohTcpTransport(DoHClientOptions{QueryTimeout: timeout})
	require.NoError(t, err)
	dohLocal, err := dohTcpTransport(DoHClientOptions{QueryTimeout: timeout, LocalAddr: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	require.Equal(t, timeout, doh.(*http.Transport).TLSHandshakeTimeout)

	// Without a configured query timeout the default applies
	tcp, err := NewDNSClient("test-hang-tcp", "127.0.0.1:53", "tcp", DNSClientOptions{})
	require.NoError(t, err)
	require.Equal(t, defaultQueryTimeout, tcp.pipeline.client.(GenericDNSClient).Timeout)

	dialDoH := func(tr http.RoundTripper) func(string) error {
		return func(addr string) error {
			_, err := tr.(*http.Transport).DialContext(context.Background(), "tcp", addr)
			return err
		}
	}
	dialers := map[string]func(addr string) error{
		"dot":               func(addr string) error { _, err := dot.pipeline.client.Dial(addr); return err },
		"doh":               dialDoH(doh),
		"doh-local-address": dialDoH(dohLocal),
	}
	for name, dial := range dialers {
		t.Run(name, func(t *testing.T) {
			addr := hangingAddr(t)
			done := make(chan error, 1)
			go func() { done <- dial(addr) }()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(5 * timeout):
				t.Fatal("still connecting long after the timeout")
			}
		})
	}
}
