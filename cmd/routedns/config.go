package main

import (
	"os"

	"github.com/BurntSushi/toml"
	rdns "github.com/folbricht/routedns"
)

type config struct {
	Title     string
	Listeners map[string]listener
	Resolvers map[string]resolver
	Groups    map[string]group
	Routers   map[string]router
}

type listener struct {
	Address   string
	Protocol  string
	Resolver  string
	CA        string
	ServerKey string `toml:"server-key"`
	ServerCrt string `toml:"server-crt"`
	MutualTLS bool   `toml:"mutual-tls"`
}

type resolver struct {
	Address       string
	Protocol      string
	DoH           doh
	CA            string
	ClientKey     string `toml:"client-key"`
	ClientCrt     string `toml:"client-crt"`
	BootstrapAddr string `toml:"bootstrap-address"`
}

// DoH-specific resolver options
type doh struct {
	Method string
}

type group struct {
	Resolvers []string
	Type      string
	Blocklist []string                // only used by "blocklist" type
	Replace   []rdns.ReplaceOperation // only used by "replace" type
}

type router struct {
	Routes []route
}

type route struct {
	Type     string
	Name     string
	Source   string
	Resolver string
}

// LoadConfig reads a config file and returns the decoded structure.
func loadConfig(name string) (config, error) {
	var c config
	f, err := os.Open(name)
	if err != nil {
		return c, err
	}
	defer f.Close()
	_, err = toml.DecodeReader(f, &c)
	return c, err
}

// Analyzes possible group depenencies and returns a list of group keys that
// if loaded in this order will be able to resolve references to other groups.
// Note, there's no recursion detection. Any recursion will lead to a panic.
func groupKeyOrder(group map[string]group) []string {
	// reformat the input
	input := make(map[string][]string)
	for k, v := range group {
		input[k] = v.Resolvers
	}
	return dependencyOrder(input)
}

// Analyzes possible router depenencies and returns a list of router keys that
// if loaded in this order will be able to resolve references to other routers.
// Note, there's no recursion detection. Any recursion will lead to a panic.
func routerKeyOrder(routers map[string]router) []string {
	// reformat the input
	input := make(map[string][]string)
	for k, v := range routers {
		for _, r := range v.Routes {
			input[k] = append(input[k], r.Resolver)
		}
	}
	return dependencyOrder(input)
}

// Untangle the dependencies as they can exist between routers, or between groups
// Returns an ordered list of keys with the later ones possibly depending on the
// earlier ones, but not the other way around. Note, there's no recursion detection.
// Any recursion will lead to a panic.
func dependencyOrder(input map[string][]string) []string {
	var resolve func(key string) []string
	resolve = func(key string) []string {
		defer delete(input, key)
		deps, ok := input[key]
		if !ok {
			return []string{}
		}
		var results []string
		for _, d := range deps {
			results = append(results, resolve(d)...)
		}
		return append(results, key)
	}

	var results []string
	for key := range input {
		results = append(results, resolve(key)...)
	}
	return results
}
