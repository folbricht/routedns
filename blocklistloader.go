package rdns

import (
	"bufio"
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

// listFailed decides what a list that could not be read means, which is the
// same wherever it was being read from and whether the list was unreachable or
// its contents unusable. AllowFailure covers a single moment, the first load:
// the list starts empty rather than keeping the process from starting, and
// whatever part of it arrived before it broke off is dropped so that a fragment
// is not served as though it were the list. Every later failure is an error, and
// the database already serving the rules keeps them, which is what a failed
// reload means everywhere.
func listFailed(log *slog.Logger, allowFailure, loaded bool, reset func(), err error) error {
	if !allowFailure || loaded {
		return err
	}
	log.Warn("failed to load blocklist, continuing without it", "error", err)
	reset()
	return nil
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
			return err
		}
	}
	return scanner.Err()
}
