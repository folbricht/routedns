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
	L.SetField(mt, "new", L.NewFunction(newMessage))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get_question": getter(messageGetQuestion),
		"set_question": setter(messageSetQuestion),
	}))
}

func newMessage(L *lua.LState) int {
	L.Push(userDataWithMetatable(L, luaMessageMetatableName, new(dns.Msg)))
	return 1
}

func messageGetQuestion(L *lua.LState, msg *dns.Msg) {
	table := L.CreateTable(len(msg.Question), 0)
	for _, q := range msg.Question {
		lv := userDataWithMetatable(L, luaQuestionMetatableName, &q)
		table.Append(lv)
	}
	L.Push(table)
}

func messageSetQuestion(L *lua.LState, msg *dns.Msg) {
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
}
