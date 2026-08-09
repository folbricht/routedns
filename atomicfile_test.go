package rdns

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Older than tmpMaxAge, so the sweep treats it as a leftover rather than a
// write that may still be in flight.
var staleAge = time.Now().Add(-2 * tmpMaxAge)

// The point of the temp-and-rename: a failure part-way through leaves the
// previous content in place rather than a truncated file, and no temp behind.
// The mode of the file being replaced is kept, since os.CreateTemp creates at
// 0600 and the rename would otherwise carry that onto the target.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "data")
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

	// A successful write replaces the content and keeps the mode.
	require.NoError(t, os.Chmod(filename, 0640))
	require.NoError(t, writeFileAtomic(filename, func(w io.Writer) error {
		_, err := io.WriteString(w, "NEW\n")
		return err
	}))
	b, err = os.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, "NEW\n", string(b))
	fi, err := os.Stat(filename)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0640), fi.Mode().Perm(), "the target's mode must survive a save")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temp file should be left behind: %v", entries)

	// A file that doesn't exist yet keeps os.CreateTemp's 0600 rather than
	// being widened by a chmod, which would bypass the process umask.
	fresh := filepath.Join(dir, "fresh")
	require.NoError(t, writeFileAtomic(fresh, func(w io.Writer) error {
		_, err := io.WriteString(w, "x")
		return err
	}))
	fi, err = os.Stat(fresh)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "a new file must not be widened past what os.CreateTemp gave it")
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

// Old temp files are reclaimed, including ones whose target is no longer in the
// config, while cache files and a write still in flight are left alone.
func TestRemoveStaleTempFiles(t *testing.T) {
	dir := t.TempDir()

	write := func(name string, age time.Time) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
		require.NoError(t, os.Chtimes(p, age, age))
		return p
	}

	stale := write(tmpPrefix+"123456", staleAge)
	// A temp whose target has since been dropped from the config: the sweep
	// has no target name to derive it from, so only a prefix scan finds it.
	orphan := write(tmpPrefix+"999999", staleAge)
	inFlight := write(tmpPrefix+"777777", time.Now())
	cache := write("cache.db", staleAge)

	// The docs suggest sharing a cache-dir, so the sweep has to leave
	// everything it didn't write alone, however much the name looks like ours.
	// The digit-stamped names are the reason the old "routedns" prefix went:
	// they're indistinguishable from a name os.CreateTemp could have produced,
	// so matching them would unlink an operator's pinned build or dated copy.
	bystanders := []string{
		"routedns.toml", "routedns.log", "routedns.pid", "routedns",
		"routedns-cache.json", "routedns123456.bak",
		"routedns2", "routedns0231", "routedns20250101",
	}
	var keep []string
	for _, n := range bystanders {
		keep = append(keep, write(n, staleAge))
	}

	removeStaleTempFiles(dir)

	require.NoFileExists(t, stale)
	require.NoFileExists(t, orphan, "a temp with no live target must still be reclaimed")
	require.FileExists(t, inFlight, "a recently written temp may still be in flight")
	require.FileExists(t, cache, "cache files must be left alone")
	for _, p := range keep {
		require.FileExists(t, p, "%s is not ours to delete", filepath.Base(p))
	}
}

// The directory comes from config, so it can contain characters that used to
// make this a malformed or over-broad glob pattern, and can be "." when the
// filename has no directory part -- which is where the binary and config file
// usually live.
func TestRemoveStaleTempFilesDirectories(t *testing.T) {
	base := t.TempDir()
	stale := func(dir string) string {
		p := filepath.Join(dir, tmpPrefix+"123456")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
		require.NoError(t, os.Chtimes(p, staleAge, staleAge))
		return p
	}

	for _, name := range []string{"cache[1]", "cache*"} {
		dir := filepath.Join(base, name)
		require.NoError(t, os.Mkdir(dir, 0755))
		p := stale(dir)
		removeStaleTempFiles(dir)
		require.NoFileExists(t, p, "sweep must work in a directory named %q", name)
	}

	cwd := filepath.Join(base, "cwd")
	require.NoError(t, os.Mkdir(cwd, 0755))
	p := stale(cwd)
	t.Chdir(cwd)
	removeStaleTempFiles(filepath.Dir("cache.json")) // "."
	removeStaleTempFiles("")
	require.FileExists(t, p, "the working directory must not be swept")
}
