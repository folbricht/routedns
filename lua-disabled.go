//go:build nolua || !(amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"errors"

	"github.com/miekg/dns"
)

// Lua replaces the real resolver in builds without the Lua interpreter: those
// made with the "nolua" tag, and those for 32-bit platforms, which the
// interpreter does not support. A configuration using a lua group fails at
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
