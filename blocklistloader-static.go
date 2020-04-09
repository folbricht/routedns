package rdns

// StaticLoader holds a fixed ruleset in memory. It's used for loading fixed
// blocklists from configuration that doesn't get refreshed.
type StaticLoader struct {
	rules []string
}

var _ BlocklistLoader = &StaticLoader{}

func NewStaticLoader(rules []string) *StaticLoader {
	return &StaticLoader{rules}
}

func (l *StaticLoader) Load() ([]string, error) {
	return l.rules, nil
}
