//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"fmt"

	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

// OPT record functions

func luaOPTType() []lua.Option {
	return []lua.Option{
		lua.Type[dns.OPT](
			lua.Hide("Hdr", "Option"),
			// methods and fields
			lua.Meta("__index", func(c *lua.Call) error {
				opt := c.Arg[*dns.OPT](0)
				switch fieldName := c.Arg[string](1); fieldName {
				case "udp_size":
					return c.Return(opt.UDPSize())
				case "do_bit":
					return c.Return(opt.Do())
				case "version":
					return c.Return(opt.Version())
				case "extended_rcode":
					return c.Return(uint8(opt.ExtendedRcode()))
				case "option":
					return c.Return(luaTable(opt.Option, luaEDNS0Value))
				case "name":
					return c.Return(opt.Hdr.Name)
				case "rtype":
					return c.Return(opt.Hdr.Rrtype)
				default:
					return c.ArgError(1, fmt.Sprintf("OPT does not have field %q", fieldName))
				}
			}),
			lua.Meta("__newindex", func(c *lua.Call) error {
				opt := c.Arg[*dns.OPT](0)
				switch fieldName := c.Arg[string](1); fieldName {
				case "udp_size":
					opt.SetUDPSize(c.Arg[uint16](2))
				case "do_bit":
					if c.Arg[bool](2) {
						opt.SetDo()
					} else {
						// Clear the DO bit: mask out bit 15 from the flags in Ttl
						opt.Hdr.Ttl &^= 1 << 15
					}
				case "version":
					opt.SetVersion(c.Arg[uint8](2))
				case "extended_rcode":
					opt.SetExtendedRcode(c.Arg[uint16](2))
				case "option":
					options, err := luaEDNS0Array(c.Value(2))
					if err != nil {
						return c.ArgError(2, err.Error())
					}
					opt.Option = options
				default:
					return c.ArgError(1, fmt.Sprintf("OPT does not have settable field %q", fieldName))
				}
				return nil
			}),
		),
		// static attributes
		lua.Module("OPT", lua.Members{
			"new": lua.GoFunc(func(c *lua.Call) error {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				if c.Len() >= 1 { // UDP size
					opt.SetUDPSize(c.Arg[uint16](0))
				}
				if c.Len() >= 2 && c.Arg[bool](1) { // DO bit
					opt.SetDo()
				}
				return c.Return(opt)
			}),
		}),
	}
}
