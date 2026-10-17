//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"fmt"

	lua "github.com/folbricht/glua"
)

func luaClientInfoType() []lua.Option {
	return []lua.Option{
		// Read-only fields: doh_path, tls_server_name, listener, protocol and
		// listener_addr. The source IP is converted in __index.
		lua.Type[ClientInfo](
			lua.Rename("DoHPath", "doh_path"),
			lua.Rename("TLSServerName", "tls_server_name"),
			lua.Hide("SourceIP"),
			lua.Meta("__index", func(c *lua.Call) error {
				ci := c.Arg[ClientInfo](0)
				switch fieldName := c.Arg[string](1); fieldName {
				case "source_ip":
					if ci.SourceIP == nil {
						return nil
					}
					return c.Return(ci.SourceIP.String())
				default:
					return c.ArgError(1, fmt.Sprintf("clientinfo does not have field %q", fieldName))
				}
			}),
		),
	}
}
