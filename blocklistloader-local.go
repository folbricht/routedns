package rdns

import (
	"bufio"
	"os"
)

// FileLoader reads blocklist rules from a local file. Used to refresh blocklists
// from a file on the local machine.
type FileLoader struct {
	filename string
}

var _ BlocklistLoader = &FileLoader{}

func NewFileLoader(filename string) *FileLoader {
	return &FileLoader{filename}
}

func (l *FileLoader) Load() ([]string, error) {
	f, err := os.Open(l.filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rules []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rules = append(rules, scanner.Text())
	}
	return rules, scanner.Err()
}
