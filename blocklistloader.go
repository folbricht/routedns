package rdns

import "errors"

type BlocklistLoader interface {
	// Returns a list of rules that can then be stored into a blocklist DB.
	Load() ([]string, error)
}

// A loader that can hand its rules over one at a time instead of building a
// slice of every one of them. A list of two million rules is some 80MB of
// strings, held for as long as it takes to build a database that is a fraction
// of that, and on a small machine that peak is what a refresh runs out of.
//
// The method is unexported, so a loader from outside the package keeps working
// through the Load path in loadRules below.
type streamingLoader interface {
	loadEach(func(rule string) error) error
}

// errBlocklistUnchanged says a list could not be read but a previous version of
// it is already loaded, so whatever is serving queries should stay as it is.
// Only loaders with AllowFailure set report it, and only once they have loaded
// something successfully.
var errBlocklistUnchanged = errors.New("blocklist unchanged")

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

// loadRules calls fn for every rule of a list, streaming them from the loader
// when it can do that and reading the whole list first when it cannot. An
// error from fn stops the load and comes back unchanged.
func loadRules(loader BlocklistLoader, fn func(rule string) error) error {
	if s, ok := loader.(streamingLoader); ok {
		return s.loadEach(fn)
	}
	rules, err := loader.Load()
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := fn(rule); err != nil {
			return err
		}
	}
	return nil
}
