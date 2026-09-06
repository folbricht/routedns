package rdns

import "errors"

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

// ruleError marks an error as coming from the database rejecting a rule rather
// than from the list failing to load. AllowFailure is about a list being
// unavailable, not about its contents being wrong, so the two must not be
// confused for one another.
type ruleError struct{ err error }

func (e ruleError) Error() string { return e.err.Error() }
func (e ruleError) Unwrap() error { return e.err }

// loadFailure reports whether err is a list that could not be read, as opposed
// to a rule the database would not take.
func loadFailure(err error) bool {
	var re ruleError
	return err != nil && !errors.As(err, &re)
}
