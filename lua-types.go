package rdns

import (
	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

func (s *LuaScript) RegisterConstants() {
	L := s.L

	// Register TypeA, TypeAAAA, etc
	for value, name := range dns.TypeToString {
		L.SetGlobal("Type"+name, lua.LNumber(value))
	}

	// Register ClassINET, etc
	for value, name := range dns.ClassToString {
		L.SetGlobal("Class"+name, lua.LNumber(value))
	}

	// Register Rcodes, RcodeNOERROR, RcodeNXDOMAIN, etc
	for value, name := range dns.RcodeToString {
		L.SetGlobal("Rcode"+name, lua.LNumber(value))
	}
}

func userDataWithMetatable(L *lua.LState, mtName string, value any) *lua.LUserData {
	ud := L.NewUserData()
	ud.Value = value
	L.SetMetatable(ud, L.GetTypeMetatable(mtName))
	return ud
}
