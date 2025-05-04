package rdns

import (
	"fmt"

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
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			question, ok := getUserDataArg[*dns.Question](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "name":
				L.Push(lua.LString(question.Name))
			case "qtype":
				L.Push(lua.LNumber(question.Qtype))
			case "qclass":
				L.Push(lua.LNumber(question.Qclass))
			default:
				L.ArgError(2, fmt.Sprintf("question does not have field %q", fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			question, ok := getUserDataArg[*dns.Question](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "name":
				question.Name = L.CheckString(3)
			case "qtype":
				question.Qtype = uint16(L.CheckNumber(3))
			case "qclass":
				question.Qclass = uint16(L.CheckNumber(3))
			default:
				L.ArgError(2, fmt.Sprintf("question does not have field %q", fieldName))
				return 0
			}
			return 0
		}))
}
