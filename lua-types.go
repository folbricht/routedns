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

	// Register ClassIN, etc
	for value, name := range dns.ClassToString {
		L.SetGlobal("Class"+name, lua.LNumber(value))
	}

	// Register Rcodes, RcodeNOERROR, RcodeNXDOMAIN, etc
	for value, name := range dns.RcodeToString {
		L.SetGlobal("Rcode"+name, lua.LNumber(value))
	}

	// Register EDNS0 option codes
	for name, value := range map[string]uint16{
		"EDNS0LLQ":          0x1,
		"EDNS0UL":           0x2,
		"EDNS0NSID":         0x3,
		"EDNS0ESU":          0x4,
		"EDNS0DAU":          0x5,
		"EDNS0DHU":          0x6,
		"EDNS0N3U":          0x7,
		"EDNS0SUBNET":       0x8,
		"EDNS0EXPIRE":       0x9,
		"EDNS0COOKIE":       0xa,
		"EDNS0TCPKEEPALIVE": 0xb,
		"EDNS0PADDING":      0xc,
		"EDNS0EDE":          0xf,
	} {
		L.SetGlobal(name, lua.LNumber(value))
	}
}

func userDataWithMetatable(L *lua.LState, mtName string, value any) *lua.LUserData {
	ud := L.NewUserData()
	ud.Value = value
	L.SetMetatable(ud, L.GetTypeMetatable(mtName))
	return ud
}
