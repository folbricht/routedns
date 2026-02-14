package rdns

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// OPT record functions

const luaOPTMetatableName = "OPT"

func (s *LuaScript) RegisterOPTType() {
	L := s.L
	mt := L.NewTypeMetatable(luaOPTMetatableName)
	L.SetGlobal(luaOPTMetatableName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(func(L *lua.LState) int {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		nArgs := L.GetTop()
		if nArgs >= 1 { // UDP size
			opt.SetUDPSize(uint16(L.CheckNumber(1)))
		}
		if nArgs >= 2 { // DO bit
			if L.CheckBool(2) {
				opt.SetDo()
			}
		}
		L.Push(userDataWithMetatable(L, luaOPTMetatableName, opt))
		return 1
	}))
	// methods and fields
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			opt, ok := getUserDataArg[*dns.OPT](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "udp_size":
				L.Push(lua.LNumber(opt.UDPSize()))
			case "do_bit":
				L.Push(lua.LBool(opt.Do()))
			case "version":
				L.Push(lua.LNumber(opt.Version()))
			case "extended_rcode":
				L.Push(lua.LNumber(uint8(opt.ExtendedRcode())))
			case "option":
				table := L.CreateTable(len(opt.Option), 0)
				for _, v := range opt.Option {
					mtName := reflect.TypeOf(v).String()
					if i := strings.LastIndex(mtName, "."); i >= 0 {
						mtName = mtName[i+1:]
					}
					lv := userDataWithMetatable(L, mtName, v)
					table.Append(lv)
				}
				L.Push(table)
			case "name":
				L.Push(lua.LString(opt.Hdr.Name))
			case "rtype":
				L.Push(lua.LNumber(opt.Hdr.Rrtype))
			default:
				L.ArgError(2, fmt.Sprintf("OPT does not have field %q", fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			opt, ok := getUserDataArg[*dns.OPT](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "udp_size":
				opt.SetUDPSize(uint16(L.CheckNumber(3)))
			case "do_bit":
				if L.CheckBool(3) {
					opt.SetDo()
				} else {
					// Clear the DO bit: mask out bit 15 from the flags in Ttl
					opt.Hdr.Ttl &^= 1 << 15
				}
			case "version":
				opt.SetVersion(uint8(L.CheckNumber(3)))
			case "extended_rcode":
				opt.SetExtendedRcode(uint16(L.CheckNumber(3)))
			case "option":
				table := L.CheckTable(3)
				n := table.Len()
				options := make([]dns.EDNS0, 0, n)
				for i := range n {
					element := table.RawGetInt(i + 1)
					ud, ok := element.(*lua.LUserData)
					if !ok {
						L.ArgError(3, fmt.Sprintf("expected userdata, got %v", element.Type().String()))
						return 0
					}
					edns0, ok := ud.Value.(dns.EDNS0)
					if !ok {
						L.ArgError(3, fmt.Sprintf("expected EDNS0, got %T", ud.Value))
						return 0
					}
					options = append(options, edns0)
				}
				opt.Option = options
			default:
				L.ArgError(2, fmt.Sprintf("OPT does not have settable field %q", fieldName))
				return 0
			}
			return 0
		}))
}
