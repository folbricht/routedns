package rdns

import (
	"bufio"
	"os"
)

// FileLoader reads blocklist rules from a local file. Used to refresh blocklists
// from a file on the local machine.
type FileLoader struct {
	filename    string
	opt         FileLoaderOptions
	lastSuccess []string
}

// FileLoaderOptions holds options for file blocklist loaders.
type FileLoaderOptions struct {
	// Don't fail when trying to load the list
	AllowFailure bool
}

var _ BlocklistLoader = &FileLoader{}

func NewFileLoader(filename string, opt FileLoaderOptions) *FileLoader {
	return &FileLoader{filename, opt, nil}
}

func (l *FileLoader) Load() (rules []string, err error) {
	log := Log.With("file", l.filename)
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

	f, err := os.Open(l.filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rules = append(rules, scanner.Text())
	}
	log.Debug("completed loading blocklist")
	return rules, scanner.Err()
}
