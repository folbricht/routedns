package rdns

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// The point of the temp-and-rename: a failure part-way through leaves the
// previous content in place rather than a truncated file, and no temp behind.
func TestWriteFileAtomic(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.WriteFile(filename, []byte("PREVIOUS\n"), 0644))

	wantErr := errors.New("boom")
	err := writeFileAtomic(filename, func(w io.Writer) error {
		// Write enough to get past the buffer and reach the file, then fail.
		for range 10000 {
			if _, err := io.WriteString(w, "partial data that should never land\n"); err != nil {
				return err
			}
		}
		return wantErr
	})
	require.ErrorIs(t, err, wantErr)

	b, err := os.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, "PREVIOUS\n", string(b), "the previous file must survive a failed write")

	entries, err := os.ReadDir(filepath.Dir(filename))
	require.NoError(t, err)
	require.Len(t, entries, 1, "the temp file must be cleaned up: %v", entries)
}

// Temp files left by a run that was killed mid-write are cleaned up, without
// touching the cache file itself or anything else in the directory.
func TestRemoveStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "cache.db")

	require.NoError(t, os.WriteFile(filename, []byte("keep"), 0644))
	require.NoError(t, os.WriteFile(filename+".tmp1234", []byte("stale"), 0644))
	require.NoError(t, os.WriteFile(filename+".tmp5678", []byte("stale"), 0644))
	// A different target's cache file must survive.
	other := filepath.Join(dir, "other.db")
	require.NoError(t, os.WriteFile(other, []byte("keep"), 0644))

	removeStaleTempFiles(filename)

	require.FileExists(t, filename)
	require.FileExists(t, other)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "only the stale temp files should be removed: %v", entries)
}

// Two writers to the same file must not mix their output. Sharing one temp
// file between them would let both write into it at independent offsets and
// then rename the mixture into place; unique temp names prevent that. Two
// blocklists pointing at the same URL with a shared cache-dir do exactly this.
//
// Repeated because the interleaving is timing-dependent: a single round only
// catches a shared temp file about one time in six.
func TestWriteFileAtomicConcurrent(t *testing.T) {
	for range 25 {
		dir := t.TempDir()
		filename := filepath.Join(dir, "data")

		var wg sync.WaitGroup
		for _, char := range []string{"a", "b"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Well past the write buffer, so the content reaches the file
				// in several chunks that can interleave.
				line := strings.Repeat(char, 99) + "\n"
				writeFileAtomic(filename, func(w io.Writer) error {
					for range 5000 {
						if _, err := io.WriteString(w, line); err != nil {
							return err
						}
					}
					return nil
				})
			}()
		}
		wg.Wait()

		b, err := os.ReadFile(filename)
		require.NoError(t, err)
		content := string(b)
		require.False(t, strings.Contains(content, "a") && strings.Contains(content, "b"),
			"the file must be one writer's output, not a mix of both")
	}
}
