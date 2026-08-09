package rdns

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// HTTPLoader reads blocklist rules from a server via HTTP(S).
type HTTPLoader struct {
	url         string
	opt         HTTPLoaderOptions
	fromDisk    bool
	lastSuccess []string
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
	l := &HTTPLoader{url, opt, opt.CacheDir != "", nil}
	if opt.CacheDir != "" {
		// Clean up temp files left behind by a run that was killed mid-write.
		removeStaleTempFiles(opt.CacheDir)
	}
	return l
}

func (l *HTTPLoader) Load() (rules []string, err error) {
	log := Log.With("url", l.url)
	log.Debug("loading blocklist")

	// If AllowFailure is enabled, return the last successfully loaded list
	// and nil
	defer func() {
		if err != nil && l.opt.AllowFailure {
			log.Warn("failed to load blocklist, continuing with previous ruleset",
				"error", err)
			rules = l.lastSuccess
			err = nil
		} else {
			l.lastSuccess = rules
		}
	}()

	// If a cache-dir was given, try to load the list from disk on first load
	if l.fromDisk {
		start := time.Now()
		l.fromDisk = false
		rules, err := l.loadFromDisk()
		if err == nil {
			log.With("load-time", time.Since(start)).Debug("loaded blocklist from cache-dir")
			return rules, err
		}
		log.Warn("unable to load cached list from disk, loading from upstream",
			"error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", l.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("got unexpected status code %d from %s", resp.StatusCode, l.url)
	}

	start := time.Now()
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		rules = append(rules, scanner.Text())
	}
	log.With("load-time", time.Since(start)).Debug("completed loading blocklist")

	// Cache the content to disk if the read from the remote server was successful
	if scanner.Err() == nil && l.opt.CacheDir != "" {
		log.Debug("writing rules to cache-dir")
		if err := l.writeToDisk(rules); err != nil {
			Log.Error("failed to write rules to cache", "error", err)
		}
	}
	return rules, scanner.Err()
}

// Loads a cached version of the list from disk. The filename is made by hashing the URL with SHA256
// and the file is expect to be in cache-dir.
func (l *HTTPLoader) loadFromDisk() ([]string, error) {
	f, err := os.Open(l.cacheFilename())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rules []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rules = append(rules, scanner.Text())
	}
	return rules, scanner.Err()
}

func (l *HTTPLoader) writeToDisk(rules []string) error {
	return writeFileAtomic(l.cacheFilename(), func(w io.Writer) error {
		for _, r := range rules {
			if _, err := io.WriteString(w, r); err != nil {
				return err
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
		return nil
	})
}

// Returns the name of the list cache file, which is the SHA256 of url in the cache-dir.
func (l *HTTPLoader) cacheFilename() string {
	name := fmt.Sprintf("%x", sha256.Sum256([]byte(l.url)))
	return filepath.Join(l.opt.CacheDir, name)
}
