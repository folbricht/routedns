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

// Load hands over the rules it was given. They are already in memory and there
// is nothing that can fail to read, so there is never anything to reset.
func (l *StaticLoader) Load(_ func(), fn func(rule string) error) error {
	for _, rule := range l.rules {
		if err := fn(rule); err != nil {
			return err
		}
	}
	return nil
}
