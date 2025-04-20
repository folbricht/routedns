package rdns

import (
	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// Question functions

func (s *LuaScript) RegisterQuestionType() {
	L := s.L
	mt := L.NewTypeMetatable(luaQuestionTypeName)
	L.SetGlobal("Question", mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(newQuestion))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get_name":   getter(questionGetName),
		"get_qtype":  getter(questionGetQType),
		"get_qclass": getter(questionGetQClass),
		"set_name":   setter(questionSetName),
		"set_qtype":  setter(questionSetQType),
		"set_qclass": setter(questionSetQClass),
	}))
}

func newQuestion(L *lua.LState) int {
	L.Push(userDataWithType(L, luaQuestionTypeName, new(dns.Question)))
	return 1
}

func questionGetName(L *lua.LState, r *dns.Question)   { L.Push(lua.LString(r.Name)) }
func questionGetQType(L *lua.LState, r *dns.Question)  { L.Push(lua.LNumber(r.Qtype)) }
func questionGetQClass(L *lua.LState, r *dns.Question) { L.Push(lua.LNumber(r.Qclass)) }

func questionSetName(L *lua.LState, r *dns.Question)   { r.Name = L.CheckString(2) }
func questionSetQType(L *lua.LState, r *dns.Question)  { r.Qtype = uint16(L.CheckInt(2)) }
func questionSetQClass(L *lua.LState, r *dns.Question) { r.Qclass = uint16(L.CheckInt(2)) }
