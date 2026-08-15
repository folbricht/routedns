//go:build nolua

package rdns

import (
	"errors"

	"github.com/miekg/dns"
)

// Lua replaces the real resolver in builds made with the "nolua" tag, which
// leave out the Lua interpreter. A configuration using a lua group fails at
// startup rather than passing queries through unmodified.
type Lua struct{}

var _ Resolver = &Lua{}

var errNoLua = errors.New("this build does not support lua")

func NewLua(id string, opt LuaOptions, resolvers ...Resolver) (*Lua, error) {
	return nil, errNoLua
}

func (r *Lua) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	return nil, errNoLua
}

func (r *Lua) String() string {
	return "lua"
}

func (r *Lua) Close() {}
