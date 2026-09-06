package rdns

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A list read from the server is cached to disk as it arrives, and the next
// loader started against the same cache-dir reads it from there. A second
// download replaces the previous content rather than leaving a longer file's
// tail behind, and the cache file must be the only thing in the cache-dir,
// which pins the temp file's location as well as its cleanup.
func TestHTTPLoaderDiskCache(t *testing.T) {
	dir := t.TempDir()
	var served []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Join(served, "\n"))
	}))
	defer srv.Close()

	served = []string{"a.example.com", "b.example.com", "c.example.com"}
	l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir})
	got, err := l.Load()
	require.NoError(t, err)
	require.Equal(t, served, got)

	// A new loader with the same cache-dir starts from the file on disk.
	cached, err := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}).Load()
	require.NoError(t, err)
	require.Equal(t, served, cached)

	// A shorter list must not leave the tail of the previous one behind.
	served = []string{"only.example.com"}
	got, err = l.Load()
	require.NoError(t, err)
	require.Equal(t, served, got)
	cached, err = NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}).Load()
	require.NoError(t, err)
	require.Equal(t, served, cached)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the cache file should remain: %v", entries)
	require.Equal(t, filepath.Base(l.cacheFilename()), entries[0].Name())
}

// A download that fails part way through must leave the cached copy alone.
func TestHTTPLoaderCacheKeptOnFailure(t *testing.T) {
	dir := t.TempDir()
	good := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !good {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, "a.example.com\nb.example.com")
	}))
	defer srv.Close()

	_, err := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}).Load()
	require.NoError(t, err)

	good = false
	l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir})
	l.fromDisk = false // force it to the network
	_, err = l.Load()
	require.Error(t, err)

	cached, err := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}).Load()
	require.NoError(t, err)
	require.Equal(t, []string{"a.example.com", "b.example.com"}, cached)
}

// With AllowFailure set, a list that has never loaded starts empty, while one
// that has loaded before keeps what it has.
func TestLoaderAllowFailure(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "list.txt")

	l := NewFileLoader(name, FileLoaderOptions{AllowFailure: true})
	rules, err := l.Load()
	require.NoError(t, err, "a list that never loaded starts empty")
	require.Empty(t, rules)

	require.NoError(t, os.WriteFile(name, []byte("a.example.com\n"), 0644))
	rules, err = l.Load()
	require.NoError(t, err)
	require.Equal(t, []string{"a.example.com"}, rules)

	require.NoError(t, os.Remove(name))
	_, err = l.Load()
	require.ErrorIs(t, err, errBlocklistUnchanged, "a loaded list keeps what it has")

	// Without AllowFailure the error surfaces as it always did.
	_, err = NewFileLoader(name, FileLoaderOptions{}).Load()
	require.Error(t, err)
	require.NotErrorIs(t, err, errBlocklistUnchanged)
}

// A body that stops short of what was promised is a partial list. It must not
// be reported as a loaded one, and the cached copy must survive it.
func TestHTTPLoaderTruncatedBody(t *testing.T) {
	dir := t.TempDir()
	truncate := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if truncate {
			w.Header().Set("Content-Length", "1000")
			fmt.Fprint(w, "half.example.com\n")
			return
		}
		fmt.Fprint(w, "a.example.com\nb.example.com")
	}))
	defer srv.Close()

	_, err := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}).Load()
	require.NoError(t, err)

	truncate = true
	for _, allowFailure := range []bool{false, true} {
		l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir, AllowFailure: allowFailure})
		l.fromDisk = false // force it to the network
		_, err = l.Load()
		require.Error(t, err, "allow-failure=%v: a partial list is not a list", allowFailure)
		require.NotErrorIs(t, err, errBlocklistUnchanged)
	}

	cached, err := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}).Load()
	require.NoError(t, err)
	require.Equal(t, []string{"a.example.com", "b.example.com"}, cached)
}

// A cache-dir that cannot be written to is worth a warning, not a failed load.
func TestHTTPLoaderUnwritableCache(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0644))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "a.example.com\nb.example.com")
	}))
	defer srv.Close()

	l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: notADir})
	l.fromDisk = false
	rules, err := l.Load()
	require.NoError(t, err, "the download worked, only the cache did not")
	require.Equal(t, []string{"a.example.com", "b.example.com"}, rules)
}
