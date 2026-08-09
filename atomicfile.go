package rdns

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Size of the buffer used when reading or writing whole cache files. Without
// buffering, callers that handle many small records issue a syscall per record.
const fileBufSize = 64 * 1024

const (
	// Marks a temp file written by writeFileAtomic. Deliberately not derived
	// from the target name: a sweep keyed on the target can't reclaim temps
	// whose target has since been removed from the config.
	tmpPrefix = ".routedns-tmp-"

	// Temps younger than this belong to a write that may still be in flight,
	// possibly in another process sharing the directory.
	tmpMaxAge = time.Hour
)

// Removes temp files in dir left behind by a writeFileAtomic call that was
// interrupted before it could rename or clean up. Errors are ignored; a
// leftover wastes space but doesn't affect correctness.
//
// Only files older than tmpMaxAge are removed, so this is safe to run while
// another writer -- including one in another process sharing the directory --
// has a write in flight. An in-flight temp is by definition freshly modified.
//
// Note os.Remove unlinks the name rather than following it, and ReadDir's
// Info is an lstat, so neither the age check nor the removal follows a symlink
// planted in the directory.
//
// Only tmpPrefix is matched. The prefix used before it was "routedns" followed
// by the digits os.CreateTemp appends, which can't be told apart from a version-
// or date-stamped file an operator keeps alongside: os.CreateTemp formats a
// random uint32 unpadded, so it emits one to ten digits and "routedns2" is a
// name it could have produced itself. This is a directory the config named for
// one particular file rather than one routedns owns, and it generally runs as
// root, so a false positive here unlinks a file we have no business touching.
func removeStaleTempFiles(dir string) {
	// Only sweep a directory the config actually named. filepath.Dir returns
	// "." for a bare filename like "cache.json", and the working directory is
	// where the binary and the config file usually live.
	if dir == "" || dir == "." {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-tmpMaxAge)
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(name, tmpPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		os.Remove(filepath.Join(dir, name))
	}
}

// Replaces the file at filename with whatever write produces, atomically. The
// content goes to a temporary file in the same directory which is then renamed
// into place, so an error part-way through leaves the previous file intact
// rather than a truncated one. The writer passed to write is buffered and
// flushed before the rename.
//
// The temp file keeps the mode of the file it replaces, since os.CreateTemp
// creates at 0600 and the rename would otherwise carry that onto the target. A
// file that doesn't exist yet keeps the 0600, which is the restrictive choice
// for data that records what's been looked up. Widening it to 0644 instead
// would ignore the process umask, since chmod(2) isn't filtered by it the way
// the mode passed to open(2) is.
//
// Two things here are load-bearing and shouldn't be simplified away:
//
// The temp has to live in the target's directory. os.Rename has no copy
// fallback and fails with EXDEV across filesystems, and the cache file is
// commonly on a tmpfs separate from wherever the system temp dir lives.
//
// The name has to stay random. os.CreateTemp opens with O_CREATE|O_EXCL, so it
// refuses to follow a symlink planted at that path, and two writers to one
// target can't end up sharing a temp file and renaming a mix of both into
// place. A name derived from the target would need os.Create, which follows a
// symlink and truncates whatever it points at -- and blocklist cache names are
// the SHA256 of the source URL, so they're predictable from the config.
func writeFileAtomic(filename string, write func(w io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(filename), tmpPrefix)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // no-op once the rename below has succeeded
	}()

	// Keep the mode of the file being replaced. Only a genuinely missing file
	// keeps os.CreateTemp's 0600: anything else means we couldn't read the mode
	// we're meant to preserve, and guessing could widen it on a cache holding
	// a record of what's been looked up.
	switch fi, err := os.Stat(filename); {
	case err == nil:
		if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}

	w := bufio.NewWriterSize(tmp, fileBufSize)
	if err := write(w); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	// Flush to disk before the rename, so a machine crash can't leave the new
	// name pointing at an empty file.
	if err := tmp.Sync(); err != nil {
		return err
	}
	// Close before renaming; Windows needs it.
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}
