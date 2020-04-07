package rdns

type BlocklistLoader interface {
	// Returns a list of rules that can then be stored into a blocklist DB.
	Load() ([]string, error)
}
