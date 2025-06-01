package rdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// EDNS0 functions

func (s *LuaScript) RegisterEDNS0Types() {
	s.registerEDNS0COOKIEType()
	s.registerEDNS0DAUType()
	s.registerEDNS0DHUType()
	s.registerEDNS0EDEType()
	s.registerEDNS0ESUType()
	s.registerEDNS0EXPIREType()
	s.registerEDNS0LLQType()
	s.registerEDNS0LOCALType()
	s.registerEDNS0N3UType()
	s.registerEDNS0NSIDType()
	s.registerEDNS0PADDINGType()
	s.registerEDNS0SUBNETType()
	s.registerEDNS0TCPKEEPALIVEType()
	s.registerEDNS0ULType()
}

func (s *LuaScript) registerEDNS0COOKIEType() {
	L := s.L
	mtName := "EDNS0_COOKIE"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_COOKIE)
			e.Code = dns.EDNS0COOKIE
			nArgs := L.GetTop()
			if nArgs >= 1 { // Cookie
				e.Cookie = L.CheckString(1)
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_COOKIE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "cookie":
				L.Push(lua.LString(e.Cookie))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_COOKIE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "cookie":
				e.Cookie = L.CheckString(3)
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0DAUType() {
	L := s.L
	mtName := "EDNS0_DAU"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_DAU)
			e.Code = dns.EDNS0DAU
			nArgs := L.GetTop()
			if nArgs >= 1 { // Alg Codes
				values, _ := getNumberSlice[uint8](L, 1)
				e.AlgCode = values
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_DAU](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "algcode":
				L.Push(numberSliceToTable(L, e.AlgCode))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_DAU](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "algcode":
				values, _ := getNumberSlice[uint8](L, 3)
				e.AlgCode = values
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0DHUType() {
	L := s.L
	mtName := "EDNS0_DHU"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_DHU)
			e.Code = dns.EDNS0DHU
			nArgs := L.GetTop()
			if nArgs >= 1 { // Alg Codes
				values, _ := getNumberSlice[uint8](L, 1)
				e.AlgCode = values
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_DHU](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "algcode":
				L.Push(numberSliceToTable(L, e.AlgCode))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_DHU](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "algcode":
				values, _ := getNumberSlice[uint8](L, 3)
				e.AlgCode = values
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0EDEType() {
	L := s.L
	mtName := "EDNS0_EDE"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_EDE)
			nArgs := L.GetTop()
			if nArgs >= 1 { // Code
				e.InfoCode = uint16(L.CheckNumber(1))
			}
			if nArgs >= 2 { // Extra Text
				e.ExtraText = L.CheckString(2)
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_EDE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "infocode":
				L.Push(lua.LNumber(e.InfoCode))
			case "extratext":
				L.Push(lua.LString(e.ExtraText))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_EDE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "infocode":
				e.InfoCode = uint16(L.CheckNumber(3))
			case "extratext":
				e.ExtraText = L.CheckString(3)
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0ESUType() {
	L := s.L
	mtName := "EDNS0_ESU"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_ESU)
			e.Code = dns.EDNS0ESU
			nArgs := L.GetTop()
			if nArgs >= 1 { // URI
				e.Uri = L.CheckString(1)
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_ESU](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "uri":
				L.Push(lua.LString(e.Uri))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_ESU](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "uri":
				e.Uri = L.CheckString(3)
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0EXPIREType() {
	L := s.L
	mtName := "EDNS0_EXPIRE"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_EXPIRE)
			e.Code = dns.EDNS0EXPIRE
			nArgs := L.GetTop()
			if nArgs >= 1 { // Expire
				e.Expire = uint32(L.CheckNumber(1))
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_EXPIRE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "expire":
				L.Push(lua.LNumber(e.Expire))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_EXPIRE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "expire":
				e.Expire = uint32(L.CheckNumber(3))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0LLQType() {
	L := s.L
	mtName := "EDNS0_LLQ"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_LLQ)
			e.Code = dns.EDNS0LLQ
			nArgs := L.GetTop()
			if nArgs >= 1 { // Version
				e.Version = uint16(L.CheckNumber(1))
			}
			if nArgs >= 2 { // Opcode
				e.Opcode = uint16(L.CheckNumber(2))
			}
			if nArgs >= 3 { // Error
				e.Error = uint16(L.CheckNumber(3))
			}
			if nArgs >= 4 { // Id
				e.Id = uint64(L.CheckNumber(4))
			}
			if nArgs >= 5 { // LeaseLife
				e.LeaseLife = uint32(L.CheckNumber(5))
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_LLQ](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "version":
				L.Push(lua.LNumber(e.Version))
			case "opcode":
				L.Push(lua.LNumber(e.Opcode))
			case "error":
				L.Push(lua.LNumber(e.Error))
			case "id":
				L.Push(lua.LNumber(e.Id))
			case "leaselife":
				L.Push(lua.LNumber(e.LeaseLife))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_LLQ](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "version":
				e.Version = uint16(L.CheckNumber(3))
			case "opcode":
				e.Opcode = uint16(L.CheckNumber(3))
			case "error":
				e.Error = uint16(L.CheckNumber(3))
			case "id":
				e.Id = uint64(L.CheckNumber(3))
			case "leaselife":
				e.LeaseLife = uint32(L.CheckNumber(3))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0LOCALType() {
	L := s.L
	mtName := "EDNS0_LOCAL"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_LOCAL)
			nArgs := L.GetTop()
			if nArgs >= 1 { // Code
				e.Code = uint16(L.CheckNumber(1))
			}
			if nArgs >= 2 { // Data
				e.Data = []byte(L.CheckString(2))
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_LOCAL](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "code":
				L.Push(lua.LNumber(e.Code))
			case "data":
				L.Push(lua.LString(e.Data))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_LOCAL](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "code":
				e.Code = uint16(L.CheckNumber(3))
			case "data":
				e.Data = []byte(L.CheckString(3))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0N3UType() {
	L := s.L
	mtName := "EDNS0_N3U"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_N3U)
			e.Code = dns.EDNS0N3U
			nArgs := L.GetTop()
			if nArgs >= 1 { // Alg Codes
				values, _ := getNumberSlice[uint8](L, 1)
				e.AlgCode = values
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_N3U](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "algcode":
				L.Push(numberSliceToTable(L, e.AlgCode))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_N3U](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "algcode":
				values, _ := getNumberSlice[uint8](L, 3)
				e.AlgCode = values
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0NSIDType() {
	L := s.L
	mtName := "EDNS0_NSID"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_NSID)
			e.Code = dns.EDNS0NSID
			nArgs := L.GetTop()
			if nArgs >= 1 { // NSID
				e.Nsid = L.CheckString(1)
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_NSID](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "nsid":
				L.Push(lua.LString(e.Nsid))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_NSID](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "nsid":
				e.Nsid = L.CheckString(3)
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0PADDINGType() {
	L := s.L
	mtName := "EDNS0_PADDING"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_PADDING)
			nArgs := L.GetTop()
			if nArgs >= 1 { // NSID
				e.Padding = []byte(L.CheckString(1))
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_PADDING](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "padding":
				L.Push(lua.LString(e.Padding))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_PADDING](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "padding":
				e.Padding = []byte(L.CheckString(3))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0SUBNETType() {
	L := s.L
	mtName := "EDNS0_SUBNET"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_SUBNET)
			e.Code = dns.EDNS0SUBNET
			nArgs := L.GetTop()
			if nArgs >= 1 { // Family
				e.Family = uint16(L.CheckNumber(1))
			}
			if nArgs >= 2 { // SourceNetmask
				e.SourceNetmask = uint8(L.CheckNumber(2))
			}
			if nArgs >= 3 { // SourceScope
				e.SourceScope = uint8(L.CheckNumber(3))
			}
			if nArgs >= 4 { // Address
				value := L.CheckString(4)
				ip := net.ParseIP(value)
				if ip == nil {
					L.ArgError(4, fmt.Sprintf("expected IP address, got %q", value))
					return 0
				}
				e.Address = ip
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_SUBNET](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "family":
				L.Push(lua.LNumber(e.Family))
			case "sourcenetmask":
				L.Push(lua.LNumber(e.SourceNetmask))
			case "sourcescope":
				L.Push(lua.LNumber(e.SourceScope))
			case "address":
				L.Push(lua.LString(e.Address.String()))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_SUBNET](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "family":
				e.Family = uint16(L.CheckNumber(3))
			case "sourcenetmask":
				e.SourceNetmask = uint8(L.CheckNumber(3))
			case "sourcescope":
				e.SourceScope = uint8(L.CheckNumber(3))
			case "address":
				value := L.CheckString(3)
				ip := net.ParseIP(value)
				if ip == nil {
					L.ArgError(4, fmt.Sprintf("expected IP address, got %q", value))
					return 0
				}
				e.Address = ip
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0TCPKEEPALIVEType() {
	L := s.L
	mtName := "EDNS0_TCP_KEEPALIVE"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_TCP_KEEPALIVE)
			e.Code = dns.EDNS0TCPKEEPALIVE
			nArgs := L.GetTop()
			if nArgs >= 1 { // Timeout
				e.Timeout = uint16(L.CheckNumber(1))
			}
			if nArgs >= 2 { // Length
				e.Length = uint16(L.CheckNumber(2))
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_TCP_KEEPALIVE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "timeout":
				L.Push(lua.LNumber(e.Timeout))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_TCP_KEEPALIVE](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "timeout":
				e.Timeout = uint16(L.CheckNumber(3))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}

func (s *LuaScript) registerEDNS0ULType() {
	L := s.L
	mtName := "EDNS0_UL"
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := new(dns.EDNS0_UL)
			e.Code = dns.EDNS0UL
			nArgs := L.GetTop()
			if nArgs >= 1 { // Lease
				e.Lease = uint32(L.CheckNumber(1))
			}
			if nArgs >= 2 { // KeyLease
				e.KeyLease = uint32(L.CheckNumber(2))
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_UL](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "option":
				L.Push(lua.LNumber(e.Option()))
				return 1
			case "lease":
				L.Push(lua.LNumber(e.Lease))
			case "keylease":
				L.Push(lua.LNumber(e.KeyLease))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[*dns.EDNS0_UL](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "lease":
				e.Lease = uint32(L.CheckNumber(3))
			case "keylease":
				e.KeyLease = uint32(L.CheckNumber(3))
			default:
				L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
				return 0
			}
			return 0
		}))
}
