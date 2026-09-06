package rdns

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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

var (
	_ BlocklistLoader = &HTTPLoader{}
	_ streamingLoader = &HTTPLoader{}
)

const httpTimeout = 30 * time.Minute

func NewHTTPLoader(url string, opt HTTPLoaderOptions) *HTTPLoader {
	l := &HTTPLoader{url, opt, opt.CacheDir != "", false}
	if opt.CacheDir != "" {
		// Clean up temp files left behind by a run that was killed mid-write.
		removeStaleTempFiles(opt.CacheDir)
	}
	return l
}

func (l *HTTPLoader) Load() ([]string, error) {
	var rules []string
	err := l.loadEach(func(rule string) error {
		rules = append(rules, rule)
		return nil
	})
	if errors.Is(err, errBlocklistEmpty) {
		return nil, nil // an incomplete list is no list, as it always was
	}
	return rules, err
}

// loadEach passes the rules on as they arrive over the wire, so a list of
// millions of them is never held in memory as a whole. See FileLoader.loadEach
// for what a failure means, which is the same here.
func (l *HTTPLoader) loadEach(fn func(rule string) error) error {
	log := Log.With("url", l.url)
	log.Debug("loading blocklist")

	start := time.Now()
	var served int
	err := l.read(log, func(rule string) error {
		served++
		return fn(rule)
	})
	if err == nil {
		l.loaded = true
		log.With("load-time", time.Since(start)).Debug("completed loading blocklist")
		return nil
	}
	if !l.opt.AllowFailure || !loadFailure(err) {
		return err
	}
	if !l.loaded { // nothing loaded yet, carry on with an empty list
		log.Warn("failed to load blocklist, continuing without it", "error", err)
		return errBlocklistEmpty
	}
	log.Warn("failed to load blocklist, continuing with the previous ruleset",
		"error", err)
	return errBlocklistUnchanged
}

func (l *HTTPLoader) read(log *slog.Logger, fn func(rule string) error) error {
	// If a cache-dir was given, try to load the list from disk on first load.
	// Only fall back to the network if nothing was passed on yet, since the
	// rules already handed over cannot be taken back.
	if l.fromDisk {
		l.fromDisk = false
		var served int
		err := l.readFile(l.cacheFilename(), func(rule string) error {
			served++
			return fn(rule)
		})
		if err == nil {
			log.Debug("loaded blocklist from cache-dir")
			return nil
		}
		if served > 0 || !loadFailure(err) {
			return err
		}
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
	var served int
	err = writeFileAtomic(l.cacheFilename(), func(w io.Writer) error {
		return scanRules(io.TeeReader(resp.Body, w), func(rule string) error {
			served++
			return fn(rule)
		})
	})

	// A cache that cannot be written is worth a warning, not a failed load, so
	// long as nothing has been read yet: the body is still there to be read
	// without it. Once rules are through, the failure is the read itself.
	if err != nil && served == 0 && loadFailure(err) {
		log.Warn("failed to write rules to cache-dir", "error", err)
		return scanRules(resp.Body, fn)
	}
	return err
}

func (l *HTTPLoader) readFile(name string, fn func(rule string) error) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return scanRules(f, fn)
}

// scanRules passes every line of r to fn as a rule.
func scanRules(r io.Reader, fn func(rule string) error) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return ruleError{err}
		}
	}
	return scanner.Err()
}

// Returns the name of the list cache file, which is the SHA256 of url in the cache-dir.
func (l *HTTPLoader) cacheFilename() string {
	name := fmt.Sprintf("%x", sha256.Sum256([]byte(l.url)))
	return filepath.Join(l.opt.CacheDir, name)
}
