//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"errors"

	lua "github.com/folbricht/glua"
)

// Error functions

// luaError is an error as scripts see it.
type luaError struct{ err error }

func luaErrorType() []lua.Option {
	return []lua.Option{
		lua.Type[luaError](
			lua.Method("error", func(c *lua.Call) error {
				return c.Return(c.Arg[*luaError](0).err.Error())
			}),
		),
		// static attributes
		lua.Module("Error", lua.Members{
			"new": lua.GoFunc(func(c *lua.Call) error {
				return c.Return(&luaError{errors.New(c.Arg[string](0))})
			}),
		}),
	}
}
