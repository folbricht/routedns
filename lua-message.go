package rdns

import (
	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// Message functions

const luaMessageMetatableName = "Message"

func (s *LuaScript) RegisterMessageType() {
	L := s.L
	mt := L.NewTypeMetatable(luaMessageMetatableName)
	L.SetGlobal(luaMessageMetatableName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(func(L *lua.LState) int {
		L.Push(userDataWithMetatable(L, luaMessageMetatableName, new(dns.Msg)))
		return 1
	}))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get_questions": getter(func(L *lua.LState, msg *dns.Msg) {
			table := L.CreateTable(len(msg.Question), 0)
			for _, q := range msg.Question {
				lv := userDataWithMetatable(L, luaQuestionMetatableName, &q)
				table.Append(lv)
			}
			L.Push(table)
		}),
		"set_questions": setter(func(L *lua.LState, msg *dns.Msg) {
			table := L.CheckTable(2)
			n := table.Len()
			questions := make([]dns.Question, 0, n)
			for i := range n {
				element := table.RawGetInt(i + 1)
				if element.Type() != lua.LTUserData {
					L.ArgError(1, "invalid type, expected userdata")
					return
				}
				lq := element.(*lua.LUserData)
				q, ok := lq.Value.(*dns.Question)
				if !ok {
					L.ArgError(1, "invalid type, expected question")
					return
				}
				questions = append(questions, *q)
			}
			msg.Question = questions
		}),
		"set_question": setter(func(L *lua.LState, msg *dns.Msg) {
			msg.SetQuestion(L.CheckString(2), uint16(L.CheckNumber(3)))
		}),
		"set_id": setter(func(L *lua.LState, msg *dns.Msg) {
			msg.Id = uint16(L.CheckInt(2))
		}),
		"get_id": getter(func(L *lua.LState, msg *dns.Msg) {
			L.Push(lua.LNumber(msg.Id))
		}),
		"set_response": setter(func(L *lua.LState, msg *dns.Msg) {
			msg.Response = L.CheckBool(2)
		}),
		"get_response": getter(func(L *lua.LState, msg *dns.Msg) {
			L.Push(lua.LBool(msg.Response))
		}),
		"set_reply": setter(func(L *lua.LState, msg *dns.Msg) {
			request, ok := getUserDataArg[*dns.Msg](L, 2)
			if !ok {
				return
			}
			msg.SetReply(request)
		}),
		"set_rcode": setter(func(L *lua.LState, msg *dns.Msg) {
			msg.Rcode = L.CheckInt(2)
		}),
		"get_rcode": getter(func(L *lua.LState, msg *dns.Msg) {
			L.Push(lua.LNumber(msg.Rcode))
		}),
		"set_rd": setter(func(L *lua.LState, msg *dns.Msg) {
			msg.RecursionDesired = L.CheckBool(2)
		}),
		"get_rd": getter(func(L *lua.LState, msg *dns.Msg) {
			L.Push(lua.LBool(msg.RecursionDesired))
		}),
		"set_ra": setter(func(L *lua.LState, msg *dns.Msg) {
			msg.RecursionAvailable = L.CheckBool(2)
		}),
		"get_ra": getter(func(L *lua.LState, msg *dns.Msg) {
			L.Push(lua.LBool(msg.RecursionAvailable))
		}),
		"set_ad": setter(func(L *lua.LState, msg *dns.Msg) {
			msg.AuthenticatedData = L.CheckBool(2)
		}),
		"get_ad": getter(func(L *lua.LState, msg *dns.Msg) {
			L.Push(lua.LBool(msg.AuthenticatedData))
		}),
	}))
}
