package rdns

import (
	"bufio"
	"os"
)

// FileLoader reads blocklist rules from a local file. Used to refresh blocklists
// from a file on the local machine.
type FileLoader struct {
	filename string
	opt      FileLoaderOptions
	loaded   bool // a load has succeeded before, so there is a ruleset to keep
}

// FileLoaderOptions holds options for file blocklist loaders.
type FileLoaderOptions struct {
	// Don't fail when trying to load the list
	AllowFailure bool
}

var _ BlocklistLoader = &FileLoader{}

func NewFileLoader(filename string, opt FileLoaderOptions) *FileLoader {
	return &FileLoader{filename, opt, false}
}

// Load reads the file a line at a time, so the whole list is never held at
// once.
//
// What a failure means depends on AllowFailure. Without it a list that could
// not be read is simply an error. With it, a list that has never loaded starts
// empty, dropping whatever part of it arrived before it broke off so that a
// fragment is not served as though it were the list, and a list that has loaded
// before is ErrBlocklistUnchanged, which leaves the database already serving
// queries in place and discards the one being built.
func (l *FileLoader) Load(reset func(), fn func(rule string) error) error {
	log := Log.With("file", l.filename)
	log.Debug("loading blocklist")

	err := l.read(fn)
	if err == nil {
		l.loaded = true
		log.Debug("completed loading blocklist")
		return nil
	}
	if !l.opt.AllowFailure || !loadFailure(err) {
		return err
	}
	if l.loaded {
		log.Warn("failed to load blocklist, continuing with the previous ruleset",
			"error", err)
		return ErrBlocklistUnchanged
	}
	log.Warn("failed to load blocklist, continuing without it", "error", err)
	reset()
	return nil
}

func (l *FileLoader) read(fn func(rule string) error) error {
	f, err := os.Open(l.filename)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return ruleError{err}
		}
	}
	return scanner.Err()
}
