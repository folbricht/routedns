package main

import (
	"bytes"
	"log/slog"
	"os"
	"sync"
	"testing"

	rdns "github.com/folbricht/routedns"
)

// logSink is where rdns.Log writes during tests. The logger is set once, in
// TestMain, and never reassigned: instantiating components starts goroutines
// that outlive the test creating them and keep reading rdns.Log, so swapping
// the global mid-run is a data race. Tests read the log through here instead.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

var logSink = &logBuffer{}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestMain(m *testing.M) {
	rdns.Log = slog.New(slog.NewTextHandler(logSink, &slog.HandlerOptions{Level: slog.LevelWarn}))
	os.Exit(m.Run())
}

// captureLog collects what the library logs during the test.
func captureLog(t *testing.T) *logBuffer {
	t.Helper()
	logSink.mu.Lock()
	defer logSink.mu.Unlock()
	logSink.buf.Reset()
	return logSink
}
