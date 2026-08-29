package main

import (
	"bytes"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/stretchr/testify/require"
)

func TestWaitForShutdownSignal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signal os.Signal
	}{
		{"SIGTERM", syscall.SIGTERM},
		{"SIGINT", os.Interrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := make(chan os.Signal, 1)
			sig <- tc.signal
			require.Equal(t, tc.signal, waitForShutdownSignal(sig))
		})
	}
}

// SIGHUP conventionally means "reload" and must not stop RouteDNS.
func TestWaitForShutdownSignalIgnoresSIGHUP(t *testing.T) {
	b := new(bytes.Buffer)
	old := rdns.Log
	rdns.Log = slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelWarn}))
	t.Cleanup(func() { rdns.Log = old })

	sig := make(chan os.Signal, 3)
	sig <- syscall.SIGHUP
	sig <- syscall.SIGHUP

	done := make(chan os.Signal, 1)
	go func() { done <- waitForShutdownSignal(sig) }()

	// Both SIGHUPs have to be consumed without returning.
	select {
	case s := <-done:
		t.Fatalf("returned on SIGHUP with %v, expected it to be ignored", s)
	case <-time.After(100 * time.Millisecond):
	}

	// A real shutdown signal still gets through afterwards.
	sig <- syscall.SIGTERM
	select {
	case s := <-done:
		require.Equal(t, syscall.SIGTERM, s)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SIGTERM")
	}

	require.Contains(t, b.String(), "ignoring signal")
	require.Equal(t, 2, bytes.Count(b.Bytes(), []byte("ignoring signal")))
}
