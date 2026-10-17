//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

// Resolver functions

// luaResolver is an upstream resolver as scripts see it.
type luaResolver struct{ r Resolver }

// luaResolverTypes makes the resolvers available to scripts as the Resolvers
// array.
func luaResolverTypes(resolvers []Resolver) []lua.Option {
	values := make([]*luaResolver, 0, len(resolvers))
	for _, r := range resolvers {
		values = append(values, &luaResolver{r})
	}
	return []lua.Option{
		lua.Type[luaResolver](lua.Method("resolve", resolverResolve)),
		lua.Global("Resolvers", values),
	}
}

func resolverResolve(c *lua.Call) error {
	r := c.Arg[*luaResolver](0)
	msg := c.Arg[*dns.Msg](1)
	ci := c.Arg[ClientInfo](2)

	resp, err := r.r.Resolve(msg, ci)

	// The upstream query isn't interrupted at the deadline, so end the
	// script once it returns past it, rather than at the interpreter's next
	// check, which can be a thousand more queries away.
	if err := c.Context().Err(); err != nil {
		return lua.Terminate(err)
	}

	// Return the answer and the error
	if err != nil {
		return c.Return2(resp, &luaError{err})
	}
	return c.Return2(resp, (*luaError)(nil))
}
