package rdns

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

// Load reads the file a line at a time. See listFailed for a list that could
// not be read.
func (l *FileLoader) Load(reset func(), fn func(rule string) error) error {
	log := Log.With("file", l.filename)
	log.Debug("loading blocklist")

	if err := readRulesFile(l.filename, fn); err != nil {
		return listFailed(log, l.opt.AllowFailure, l.loaded, reset, err)
	}
	l.loaded = true
	log.Debug("completed loading blocklist")
	return nil
}
