package rdns

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Asserts that filename is the only thing in its directory, i.e. that the
// atomic write renamed its temp file into place or cleaned it up. Every
// caller of writeFileAtomic wants this, so it lives here rather than being
// spelled out at each call site.
func requireOnlyFile(t *testing.T, filename string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(filename))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temp file should be left behind: %v", entries)
	require.Equal(t, filepath.Base(filename), entries[0].Name())
}

func TestWriteFileAtomic(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data")

	require.NoError(t, writeFileAtomic(filename, func(w *bufio.Writer) error {
		_, err := w.WriteString("hello\n")
		return err
	}))

	b, err := os.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, "hello\n", string(b))
	requireOnlyFile(t, filename)
}

// The point of the temp-and-rename: a failure part-way through must leave the
// previous content in place rather than a truncated file.
func TestWriteFileAtomicLeavesPreviousOnError(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.WriteFile(filename, []byte("PREVIOUS\n"), 0644))

	wantErr := errors.New("boom")
	err := writeFileAtomic(filename, func(w *bufio.Writer) error {
		// Write enough to get past the buffer and reach the file, then fail.
		for range 10000 {
			if _, err := w.WriteString("partial data that should never land\n"); err != nil {
				return err
			}
		}
		return wantErr
	})
	require.ErrorIs(t, err, wantErr)

	b, err := os.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, "PREVIOUS\n", string(b), "the previous file must survive a failed write")
	requireOnlyFile(t, filename)
}

// Writing into a directory that doesn't exist fails rather than panicking,
// and reports the error to the caller.
func TestWriteFileAtomicMissingDir(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "missing", "data")
	err := writeFileAtomic(filename, func(w *bufio.Writer) error {
		_, err := w.WriteString("x")
		return err
	})
	require.Error(t, err)
}
