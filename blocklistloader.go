package rdns

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"os"
)

type BlocklistLoader interface {
	// Load calls rule for every rule of the list. Rules are handed over as
	// they are read rather than collected first, so a list of millions of them
	// is never held in memory as a whole: two million rules are some 80MB of
	// strings, kept for as long as it takes to build a database that is a
	// fraction of that, and on a small machine that peak is what a refresh runs
	// out of.
	//
	// Rules that have been passed on cannot be taken back, so a loader that
	// abandons a list part way through, either because it broke off or because
	// the rest of it is coming from somewhere else, calls reset first to drop
	// what it handed over. A fragment must never be built into a database and
	// served as though it were the list.
	Load(reset func(), rule func(string) error) error
}

// ErrBlocklistUnchanged says a list could not be read but a previous version of
// it is already loaded, so whatever is serving queries should stay as it is.
// Only loaders with AllowFailure set report it, and only once they have loaded
// something successfully. A caller that sets AllowFailure has to expect it: it
// means there are no new rules, not that anything went wrong.
var ErrBlocklistUnchanged = errors.New("blocklist unchanged")

// listFailed decides what a list that could not be read means, which is the
// same wherever it was being read from. Without AllowFailure it is simply an
// error. With it, a list that has never loaded starts empty, dropping whatever
// part of it arrived before it broke off so that a fragment is not served as
// though it were the list, and a list that has loaded before is
// ErrBlocklistUnchanged, which leaves the database already serving queries in
// place and discards the one being built.
func listFailed(log *slog.Logger, allowFailure, loaded bool, reset func(), err error) error {
	if !allowFailure || isRuleError(err) {
		return err
	}
	if loaded {
		log.Warn("failed to load blocklist, continuing with the previous ruleset",
			"error", err)
		return ErrBlocklistUnchanged
	}
	log.Warn("failed to load blocklist, continuing without it", "error", err)
	reset()
	return nil
}

// ruleError marks an error as coming from the database rejecting a rule rather
// than from the list failing to load. AllowFailure is about a list being
// unavailable, not about its contents being wrong, so the two must not be
// confused for one another.
type ruleError struct{ err error }

func (e ruleError) Error() string { return e.err.Error() }
func (e ruleError) Unwrap() error { return e.err }

// isRuleError reports whether err is a rule the database would not take, as
// opposed to a list that could not be read.
func isRuleError(err error) bool {
	var re ruleError
	return errors.As(err, &re)
}

// readRulesFile passes every line of the named file to fn as a rule.
func readRulesFile(name string, fn func(rule string) error) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return scanRules(f, fn)
}

// scanRules passes every line of r to fn as a rule. A list arrives as a stream
// of lines whatever it came from, so this is the one place one is read.
func scanRules(r io.Reader, fn func(rule string) error) error {
	scanner := bufio.NewScanner(r)
	// A list is read in one pass and the lines are short, so give the scanner
	// a buffer worth a read rather than the 4KB it starts with. The limit on a
	// single line stays where bufio puts it.
	scanner.Buffer(make([]byte, 64*1024), bufio.MaxScanTokenSize)
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return ruleError{err}
		}
	}
	return scanner.Err()
}
