package rdns

import (
	"bufio"
	"io"
	"log/slog"
	"os"
)

type BlocklistLoader interface {
	// Load calls rule for every rule as it is read rather than collecting them
	// first, so a list of millions is never held whole: two million rules are
	// some 80MB of strings against a database a fraction of that size.
	//
	// Rules already passed on cannot be taken back, so a loader that abandons
	// a list part way through calls reset first. A fragment must never be
	// served as though it were the list.
	Load(reset func(), rule func(string) error) error
}

// listFailed decides what a list that could not be read means, whether it was
// unreachable or its contents unusable. AllowFailure covers the first load
// only: the list starts empty, dropping any fragment that arrived, rather than
// keeping the process from starting. Later failures are errors, and the
// database already serving the rules keeps them.
func listFailed(log *slog.Logger, allowFailure, loaded bool, reset func(), err error) error {
	if !allowFailure || loaded {
		return err
	}
	log.Warn("failed to load blocklist, continuing without it", "error", err)
	reset()
	return nil
}

func readRulesFile(name string, fn func(rule string) error) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return scanRules(f, fn)
}

// scanRules is the one place a list is read: a stream of lines, whatever it
// came from.
func scanRules(r io.Reader, fn func(rule string) error) error {
	scanner := bufio.NewScanner(r)
	// A buffer worth a read rather than the 4KB bufio starts with. The limit
	// on a single line stays where bufio puts it.
	scanner.Buffer(make([]byte, 64*1024), bufio.MaxScanTokenSize)
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}
