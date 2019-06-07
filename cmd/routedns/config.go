package main

import (
	"os"

	"github.com/BurntSushi/toml"
)

type config struct {
	Title     string
	Listeners map[string]listener
	Resolvers map[string]resolver
	Groups    map[string]group
	Routers   map[string]router
}

type listener struct {
	Address  string
	Protocol string
	Resolver string
}

type resolver struct {
	Address  string
	Protocol string
}

type group struct {
	Resolvers []string
	Type      string
}

type router struct {
	Routes []route
}

type route struct {
	Type     string
	Name     string
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
