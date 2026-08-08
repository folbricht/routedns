package rdns

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
)

// Size of the buffer used when reading or writing whole cache files. Without
// buffering, callers that handle many small records issue a syscall per record.
const fileBufSize = 64 * 1024

// Marks the temporary files written by writeFileAtomic, so leftovers from a
// crash can be identified and removed.
const tmpSuffix = ".tmp"

// Removes temp files left next to filename by a writeFileAtomic call that was
// interrupted before it could rename or clean up. Errors are ignored; a
// leftover file wastes space but doesn't affect correctness.
//
// Call this at startup, not before each write: a leftover can only come from a
// previous run, and the glob would otherwise match, and delete, the temp file
// of a write that's currently in flight.
func removeStaleTempFiles(filename string) {
	matches, err := filepath.Glob(filename + tmpSuffix + "*")
	if err != nil {
		return
	}
	for _, m := range matches {
		os.Remove(m)
	}
}

// Replaces the file at filename with whatever write produces, atomically. The
// content goes to a temporary file next to it which is then renamed into place,
// so an error part-way through leaves the previous file intact rather than a
// truncated one. The writer passed to write is buffered and flushed before the
// rename.
//
// The temp file gets a unique name rather than one derived from the target.
// Two writers to the same file would otherwise share one temp file, writing
// into it at independent offsets and renaming the result into place: not a
// lost update but a corrupt mix of both. Any leftover from a crash between
// writing and renaming is cleaned up by removeStaleTempFiles at startup.
func writeFileAtomic(filename string, write func(w io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+tmpSuffix)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // no-op once the rename below has succeeded
	}()

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
