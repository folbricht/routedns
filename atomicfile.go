package rdns

import (
	"bufio"
	"os"
	"path/filepath"
)

// Size of the buffer used when reading or writing whole cache files. Without
// buffering, callers that handle many small records issue a syscall per record.
const fileBufSize = 64 * 1024

// Replaces the file at filename with whatever write produces, atomically.
// The content goes to a temporary file in the same directory which is then
// renamed into place, so an error part-way through leaves the previous file
// intact rather than a truncated one. The writer passed to write is buffered;
// it's flushed and synced before the rename.
//
// The temp file is fsync'ed before the rename, so the rename can't be made
// durable ahead of the data it points at -- without that, a machine crash
// (rather than a process crash) can leave the new name resolving to an empty
// file. The containing directory is not synced, so the rename itself may still
// be lost on crash; that leaves the previous file in place, which is the
// outcome this function promises.
func writeFileAtomic(filename string, write func(w *bufio.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()        // no-op if the close below already succeeded
		os.Remove(tmpName) // no-op once the rename below has succeeded
	}()

	w := bufio.NewWriterSize(tmp, fileBufSize)
	if err := write(w); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	// Close before renaming; Windows needs it.
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}
