//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"context"
	"fmt"

	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

type Lua struct {
	id      string
	resolve func(context.Context, *dns.Msg, ClientInfo) (lua.Pair[*dns.Msg, *luaError], error)

	opt LuaOptions
}

var _ Resolver = &Lua{}

func NewLua(id string, opt LuaOptions, resolvers ...Resolver) (*Lua, error) {
	if opt.Timeout == 0 {
		opt.Timeout = defaultLuaTimeout
	}
	r := &Lua{id: id, opt: opt}

	rt, err := newLuaRuntime(!opt.NoSandbox, resolvers)
	if err != nil {
		return nil, err
	}

	// Loading runs the top level of the script and freezes what it built, so
	// that every query can share the one script.
	ctx, cancel := r.context()
	defer cancel()
	script, err := rt.Load(ctx, id, opt.Script)
	if err != nil {
		return nil, err
	}

	// The script must contain a Resolve() function which is the entry point
	r.resolve, err = script.Func2[*dns.Msg, ClientInfo, lua.Pair[*dns.Msg, *luaError]]("Resolve")
	if err != nil {
		return nil, fmt.Errorf("no Resolve() function found in lua script: %w", err)
	}
	return r, nil
}

func (r *Lua) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)

	// The script is handed the query to read, to pass on and to change as it
	// sees fit, which it may not do to the caller's message. Copy it, which is
	// nothing next to running a script.
	q = q.Copy()

	ctx, cancel := r.context()
	defer cancel()

	// Call the "Resolve" function in the script, which returns an answer and
	// an error, either of which may be nil.
	ret, err := r.resolve(ctx, q, ci)
	if err != nil {
		log.Error("failed to run lua script", "error", err)
		return nil, err
	}
	if ret.Second != nil {
		return ret.First, ret.Second.err
	}
	return ret.First, nil
}

// context bounds a run of the script by the configured timeout. The
// interpreter checks for cancellation between instructions, so a loop with no
// exit is cut off. Time spent inside a Go call, an upstream resolver above all,
// is not interrupted but does count towards the limit.
func (r *Lua) context() (context.Context, context.CancelFunc) {
	if r.opt.Timeout < 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), r.opt.Timeout)
}

func (r *Lua) String() string {
	return r.id
}
