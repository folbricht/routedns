package rdns

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// collectRules loads a list into a slice, which is how these tests read what a
// loader hands over. Rules arrive one at a time, and a loader that gives up on
// a list resets what it already passed on.
func collectRules(l BlocklistLoader) ([]string, error) {
	var rules []string
	err := l.Load(
		func() { rules = nil },
		func(rule string) error {
			rules = append(rules, rule)
			return nil
		})
	return rules, err
}

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
	got, err := collectRules(l)
	require.NoError(t, err)
	require.Equal(t, served, got)

	// A new loader with the same cache-dir starts from the file on disk.
	cached, err := collectRules(NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}))
	require.NoError(t, err)
	require.Equal(t, served, cached)

	// A shorter list must not leave the tail of the previous one behind.
	served = []string{"only.example.com"}
	got, err = collectRules(l)
	require.NoError(t, err)
	require.Equal(t, served, got)
	cached, err = collectRules(NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}))
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

	_, err := collectRules(NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}))
	require.NoError(t, err)

	good = false
	l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir})
	l.fromDisk = false // force it to the network
	_, err = collectRules(l)
	require.Error(t, err)

	cached, err := collectRules(NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}))
	require.NoError(t, err)
	require.Equal(t, []string{"a.example.com", "b.example.com"}, cached)
}

// A cached copy that cannot be used is dropped and the list read again from
// upstream, whether it broke off or carried a rule the database refuses.
func TestHTTPLoaderCacheFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "a.example.com\nb.example.com")
	}))
	defer srv.Close()

	for name, cached := range map[string]string{
		"broke off": "cached.example.com\n" + strings.Repeat("x", 100_000),
		"refused":   "cached.example.com\nrefused.example.com\n",
	} {
		t.Run(name, func(t *testing.T) {
			l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: t.TempDir()})
			require.NoError(t, os.WriteFile(l.cacheFilename(), []byte(cached), 0644))

			var rules []string
			err := l.Load(func() { rules = nil }, func(rule string) error {
				if rule == "refused.example.com" {
					return errors.New("the database will not take this rule")
				}
				rules = append(rules, rule)
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, []string{"a.example.com", "b.example.com"}, rules)
		})
	}
}

// AllowFailure covers the first load: a list that has never loaded starts
// empty. Once it has loaded, a failure is reported like any other, and the
// database already serving its rules is what keeps them.
func TestLoaderAllowFailure(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "list.txt")

	l := NewFileLoader(name, FileLoaderOptions{AllowFailure: true})
	rules, err := collectRules(l)
	require.NoError(t, err, "a list that never loaded starts empty")
	require.Empty(t, rules)

	require.NoError(t, os.WriteFile(name, []byte("a.example.com\n"), 0644))
	rules, err = collectRules(l)
	require.NoError(t, err)
	require.Equal(t, []string{"a.example.com"}, rules)

	require.NoError(t, os.Remove(name))
	_, err = collectRules(l)
	require.Error(t, err, "a list that has loaded reports a failure rather than starting empty")

	// Without AllowFailure the error surfaces as it always did.
	_, err = collectRules(NewFileLoader(name, FileLoaderOptions{}))
	require.Error(t, err)
}

// A body that stops short of what was promised is a list that could not be
// read: an error, no part of the fragment served, and the cached copy left
// alone.
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

	_, err := collectRules(NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}))
	require.NoError(t, err)

	truncate = true
	l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir})
	l.fromDisk = false // force it to the network
	_, err = collectRules(l)
	require.Error(t, err, "without allow-failure a partial list is an error")

	// With allow-failure and nothing loaded yet, the fragment is dropped and
	// the list is empty, which is what an unreadable list has always done.
	allow := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir, AllowFailure: true})
	allow.fromDisk = false
	rules, err := collectRules(allow)
	require.NoError(t, err)
	require.Empty(t, rules, "a fragment of a list must not be served as the list")

	truncate = false
	cached, err := collectRules(NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir}))
	require.NoError(t, err)
	require.Equal(t, []string{"a.example.com", "b.example.com"}, cached)
}

// The database built from a list that broke off must hold none of it, not the
// part that arrived before it broke.
func TestPartialListDiscarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprint(w, "half.example.com\nalso.example.com\n")
	}))
	defer srv.Close()

	loader := NewHTTPLoader(srv.URL, HTTPLoaderOptions{AllowFailure: true})
	for _, db := range map[string]func() (BlocklistDB, error){
		"domain":  func() (BlocklistDB, error) { return NewDomainDB("l", loader) },
		"compact": func() (BlocklistDB, error) { return NewDomainCompactDB("l", loader) },
	} {
		m, err := db()
		require.NoError(t, err)
		for _, q := range []string{"half.example.com.", "also.example.com."} {
			msg := new(dns.Msg)
			msg.SetQuestion(q, dns.TypeA)
			_, _, _, ok := m.Match(msg)
			require.False(t, ok, "query %s came from a list that never finished loading", q)
		}
	}
}

// A cache that cannot be written is worth a warning, not a failed load: the
// rules are in hand either way, whether the file could not be opened at all or
// the rename at the end failed.
func TestHTTPLoaderCacheWriteFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "a.example.com\nb.example.com")
	}))
	defer srv.Close()

	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0644))
	unwritable := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: notADir})

	// A directory where the cache file belongs: the rename at the end fails.
	taken := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: t.TempDir()})
	require.NoError(t, os.Mkdir(taken.cacheFilename(), 0755))

	for _, l := range []*HTTPLoader{unwritable, taken} {
		l.fromDisk = false
		rules, err := collectRules(l)
		require.NoError(t, err, "the list arrived, only the cache write failed")
		require.Equal(t, []string{"a.example.com", "b.example.com"}, rules)
	}
}

// A cache write that fails part way through a download is what a cache-dir
// filling up looks like, since the file is buffered and flushes as it fills.
// The body still arrives in full, so every rule has to be passed on and only
// the cache write reported as failed.
func TestCacheWriteFailsMidList(t *testing.T) {
	body := strings.Repeat("a.example.com\n", 5000)
	var rules []string
	scanErr, cacheErr := cacheWhileReading(
		strings.NewReader(body),
		&failingWriter{after: 100},
		func(rule string) error {
			rules = append(rules, rule)
			return nil
		})
	require.NoError(t, scanErr, "the list read fine, only the cache did not")
	require.Error(t, cacheErr)
	require.Len(t, rules, 5000, "every rule of the list must still be passed on")
}

// failingWriter takes `after` bytes and then fails, as a full disk does.
type failingWriter struct{ after int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("no space left on device")
	}
	if len(p) > w.after {
		n := w.after
		w.after = 0
		return n, errors.New("no space left on device")
	}
	w.after -= len(p)
	return len(p), nil
}

// A line longer than the scanner's buffer is a failed read of the list, not a
// cache problem, and must not be retried on a body already partly consumed.
func TestHTTPLoaderOverlongLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100_000)+"\na.example.com\nb.example.com")
	}))
	defer srv.Close()

	for _, dir := range []string{"", t.TempDir()} {
		l := NewHTTPLoader(srv.URL, HTTPLoaderOptions{CacheDir: dir})
		l.fromDisk = false
		rules, err := collectRules(l)
		require.Error(t, err, "cache-dir=%q", dir)
		require.Empty(t, rules)
	}
}
