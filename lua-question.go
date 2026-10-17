//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

// Question functions

func luaQuestionType() []lua.Option {
	return []lua.Option{
		// Fields: name, qtype, qclass
		lua.Type[dns.Question](lua.Writable("Name", "Qtype", "Qclass")),
		// static attributes
		lua.Module("Question", lua.Members{
			"new": lua.GoFunc(func(c *lua.Call) error {
				return c.Return(&dns.Question{
					Name:   c.Opt[string](0, ""),
					Qtype:  c.Opt[uint16](1, 0),
					Qclass: c.Opt[uint16](2, dns.ClassINET),
				})
			}),
		}),
	}
}
