package rdns

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The disk cache round-trips through writeToDisk/loadFromDisk. This also pins
// the temp file to the cache-dir: writeFileAtomic derives the directory from
// the target filename, which must resolve to opt.CacheDir.
func TestHTTPLoaderDiskCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l := NewHTTPLoader("https://example.com/list.txt", HTTPLoaderOptions{CacheDir: dir})

	rules := []string{"a.example.com", "b.example.com", "c.example.com"}
	require.NoError(t, l.writeToDisk(rules))

	got, err := l.loadFromDisk()
	require.NoError(t, err)
	require.Equal(t, rules, got)

	// The list must land at the hashed cache filename, with no temp file
	// left behind and nothing written outside the cache-dir.
	requireOnlyFile(t, l.cacheFilename())
}

// Rewriting an existing cache replaces it rather than appending, and leaves
// no temp file behind.
func TestHTTPLoaderDiskCacheOverwrite(t *testing.T) {
	dir := t.TempDir()
	l := NewHTTPLoader("https://example.com/list.txt", HTTPLoaderOptions{CacheDir: dir})

	require.NoError(t, l.writeToDisk([]string{"old1.example.com", "old2.example.com"}))
	require.NoError(t, l.writeToDisk([]string{"new.example.com"}))

	got, err := l.loadFromDisk()
	require.NoError(t, err)
	require.Equal(t, []string{"new.example.com"}, got)
	requireOnlyFile(t, l.cacheFilename())
}

// A missing cache-dir is reported as an error rather than silently dropping
// the list; Load() logs it and carries on with the fetched rules.
func TestHTTPLoaderDiskCacheMissingDir(t *testing.T) {
	l := NewHTTPLoader("https://example.com/list.txt", HTTPLoaderOptions{
		CacheDir: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	require.Error(t, l.writeToDisk([]string{"a.example.com"}))
}
