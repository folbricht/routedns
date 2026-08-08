package rdns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The disk cache round-trips through writeToDisk/loadFromDisk, and a rewrite
// replaces the previous content rather than leaving a longer file's tail
// behind. The cache file must be the only thing in the cache-dir, which pins
// the temp file's location as well as its cleanup.
func TestHTTPLoaderDiskCache(t *testing.T) {
	dir := t.TempDir()
	l := NewHTTPLoader("https://example.com/list.txt", HTTPLoaderOptions{CacheDir: dir})

	rules := []string{"a.example.com", "b.example.com", "c.example.com"}
	require.NoError(t, l.writeToDisk(rules))

	got, err := l.loadFromDisk()
	require.NoError(t, err)
	require.Equal(t, rules, got)

	// A shorter list must not leave the tail of the previous one behind.
	require.NoError(t, l.writeToDisk([]string{"only.example.com"}))
	got, err = l.loadFromDisk()
	require.NoError(t, err)
	require.Equal(t, []string{"only.example.com"}, got)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the cache file should remain: %v", entries)
	require.Equal(t, filepath.Base(l.cacheFilename()), entries[0].Name())
}
