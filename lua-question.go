package rdns

import (
	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// Question functions

const luaQuestionMetatableName = "Question"

func (s *LuaScript) RegisterQuestionType() {
	L := s.L
	mt := L.NewTypeMetatable(luaQuestionMetatableName)
	L.SetGlobal(luaQuestionMetatableName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			q := &dns.Question{Qclass: dns.ClassINET}
			nArgs := L.GetTop()
			if nArgs >= 1 { // Name provided
				q.Name = L.CheckString(1)
			}
			if nArgs >= 2 { // Name and type
				q.Qtype = uint16(L.CheckNumber(2))
			}
			if nArgs >= 3 { // Name, type and class
				q.Qclass = uint16(L.CheckNumber(3))
			}
			L.Push(userDataWithMetatable(L, luaQuestionMetatableName, q))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get_name":   getter(func(L *lua.LState, r *dns.Question) { L.Push(lua.LString(r.Name)) }),
		"get_qtype":  getter(func(L *lua.LState, r *dns.Question) { L.Push(lua.LNumber(r.Qtype)) }),
		"get_qclass": getter(func(L *lua.LState, r *dns.Question) { L.Push(lua.LNumber(r.Qclass)) }),
		"set_name":   setter(func(L *lua.LState, r *dns.Question) { r.Name = L.CheckString(2) }),
		"set_qtype":  setter(func(L *lua.LState, r *dns.Question) { r.Qtype = uint16(L.CheckInt(2)) }),
		"set_qclass": setter(func(L *lua.LState, r *dns.Question) { r.Qclass = uint16(L.CheckInt(2)) }),
	}))
}
