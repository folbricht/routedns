package rdns

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"
)

// HTTPLoader reads blocklist rules from a server via HTTP(S).
type HTTPLoader struct {
	url      string
	opt      HTTPLoaderOptions
	fromDisk bool
	loaded   bool // a load has succeeded before, so there is a ruleset to keep
}

// HTTPLoaderOptions holds options for HTTP blocklist loaders.
type HTTPLoaderOptions struct {
	CacheDir string

	// Don't fail when trying to load the list
	AllowFailure bool
}

var _ BlocklistLoader = &HTTPLoader{}

const httpTimeout = 30 * time.Minute

func NewHTTPLoader(url string, opt HTTPLoaderOptions) *HTTPLoader {
	l := &HTTPLoader{url, opt, opt.CacheDir != "", false}
	if opt.CacheDir != "" {
		// Clean up temp files left behind by a run that was killed mid-write.
		removeStaleTempFiles(opt.CacheDir)
	}
	return l
}

// Load passes the rules on as they arrive over the wire, so a list of millions
// of them is never held in memory as a whole. See listFailed for what a list
// that could not be read means.
func (l *HTTPLoader) Load(reset func(), fn func(rule string) error) error {
	log := Log.With("url", l.url)
	log.Debug("loading blocklist")

	start := time.Now()
	if err := l.read(log, reset, fn); err != nil {
		return listFailed(log, l.opt.AllowFailure, l.loaded, reset, err)
	}
	l.loaded = true
	log.With("load-time", time.Since(start)).Debug("completed loading blocklist")
	return nil
}

func (l *HTTPLoader) read(log *slog.Logger, reset func(), fn func(rule string) error) error {
	// If a cache-dir was given, try to load the list from disk on first load,
	// and fall back to the network when that fails. Whatever a cached copy
	// handed over before it broke off is dropped first, so the list that
	// arrives from upstream is the only one built.
	if l.fromDisk {
		l.fromDisk = false
		err := readRulesFile(l.cacheFilename(), fn)
		if err == nil {
			log.Debug("loaded blocklist from cache-dir")
			return nil
		}
		if isRuleError(err) {
			return err // the database refused a rule, another copy will not help
		}
		reset()
		log.Warn("unable to load cached list from disk, loading from upstream",
			"error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", l.url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("got unexpected status code %d from %s", resp.StatusCode, l.url)
	}

	if l.opt.CacheDir == "" {
		return scanRules(resp.Body, fn)
	}

	// Write the list to the cache as it is read rather than keeping it to
	// write afterwards. The file is only renamed into place if the whole body
	// arrives, so a failed download leaves the previous cache alone.
	log.Debug("writing rules to cache-dir")
	var scanErr error
	var opened bool
	err = writeFileAtomic(l.cacheFilename(), func(w io.Writer) error {
		opened = true
		var cacheErr error
		scanErr, cacheErr = cacheWhileReading(resp.Body, w, fn)
		if scanErr != nil {
			return scanErr
		}
		return cacheErr
	})

	// A cache that cannot be written is worth reporting, not failing the load
	// over: the rules are in hand either way. The two have to be told apart by
	// which one failed rather than by how far the read got, because the file
	// is buffered and its flush, sync and rename all happen after the body has
	// been read and every rule passed on.
	switch {
	case !opened:
		// Nothing has been read yet, so the body is still there to take
		// without a cache to write it to.
		log.Error("failed to write rules to cache-dir", "error", err)
		return scanRules(resp.Body, fn)
	case scanErr != nil:
		return scanErr
	case err != nil:
		log.Error("failed to write rules to cache-dir", "error", err)
	}
	return nil
}

// cacheWhileReading passes every rule read from r to fn and writes it to w on
// the way past, keeping the two failures apart. A cache that cannot be written
// must not look like a list that broke off, so the write error is kept here
// rather than raised where the read would report it.
func cacheWhileReading(r io.Reader, w io.Writer, fn func(rule string) error) (scanErr, cacheErr error) {
	write := func(s string) {
		if cacheErr == nil {
			_, cacheErr = io.WriteString(w, s)
		}
	}
	scanErr = scanRules(r, func(rule string) error {
		write(rule)
		write("\n")
		return fn(rule)
	})
	return scanErr, cacheErr
}

// Returns the name of the list cache file, which is the SHA256 of url in the cache-dir.
func (l *HTTPLoader) cacheFilename() string {
	name := fmt.Sprintf("%x", sha256.Sum256([]byte(l.url)))
	return filepath.Join(l.opt.CacheDir, name)
}
