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

var (
	_ BlocklistLoader = &FileLoader{}
	_ streamingLoader = &FileLoader{}
)

func NewFileLoader(filename string, opt FileLoaderOptions) *FileLoader {
	return &FileLoader{filename, opt, false}
}

func (l *FileLoader) Load() ([]string, error) {
	var rules []string
	err := l.loadEach(func(rule string) error {
		rules = append(rules, rule)
		return nil
	})
	return rules, err
}

// loadEach reads the file a line at a time, so the whole list is never held at
// once.
//
// What a failure means depends on how far it got. Without AllowFailure it is
// simply an error. With it, a list that could not be opened is no rules at all
// when none have ever loaded, and errBlocklistUnchanged once some have, which
// leaves the database already serving queries in place. A list that broke off
// part way through is an error either way: what has been passed on cannot be
// taken back, so the fragment must not be built into a database and served as
// though it were the list.
func (l *FileLoader) loadEach(fn func(rule string) error) error {
	log := Log.With("file", l.filename)
	log.Debug("loading blocklist")

	var served int
	err := l.read(func(rule string) error {
		served++
		return fn(rule)
	})
	if err == nil {
		l.loaded = true
		log.Debug("completed loading blocklist")
		return nil
	}
	if !l.opt.AllowFailure || !loadFailure(err) {
		return err
	}
	if served > 0 {
		// Part of the list is already through, so what is being built holds a
		// fragment of the rules and has to be thrown away rather than served.
		return err
	}
	if !l.loaded { // nothing loaded yet, carry on with an empty list
		log.Warn("failed to load blocklist, continuing without it", "error", err)
		return nil
	}
	log.Warn("failed to load blocklist, continuing with the previous ruleset",
		"error", err)
	return errBlocklistUnchanged
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
