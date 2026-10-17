//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package main

import (
	"path/filepath"
	"testing"

	rdns "github.com/folbricht/routedns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type nopResolver struct{}

func (nopResolver) Resolve(q *dns.Msg, ci rdns.ClientInfo) (*dns.Msg, error) { return nil, nil }
func (nopResolver) String() string                                           { return "nop" }

// The scripts in the shipped example configs have to load.
func TestExampleConfigLuaScriptsLoad(t *testing.T) {
	files, err := filepath.Glob("example-config/*.toml")
	require.NoError(t, err)

	for _, file := range files {
		cfg, err := loadConfig(file)
		require.NoError(t, err)
		for id, g := range cfg.Groups {
			if g.Type != "lua" {
				continue
			}
			t.Run(filepath.Base(file)+"/"+id, func(t *testing.T) {
				resolvers := make([]rdns.Resolver, len(g.Resolvers))
				for i := range resolvers {
					resolvers[i] = nopResolver{}
				}
				_, err := rdns.NewLua(id, rdns.LuaOptions{Script: g.LuaScript}, resolvers...)
				require.NoError(t, err)
			})
		}
	}
}
