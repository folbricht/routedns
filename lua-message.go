package rdns

import (
	"fmt"

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
	// methods and fields
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			msg, ok := getUserDataArg[*dns.Msg](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "questions":
				table := L.CreateTable(len(msg.Question), 0)
				for _, q := range msg.Question {
					lv := userDataWithMetatable(L, luaQuestionMetatableName, &q)
					table.Append(lv)
				}
				L.Push(table)
			case "id":
				L.Push(lua.LNumber(msg.Id))
			case "response":
				L.Push(lua.LBool(msg.Response))
			case "rcode":
				L.Push(lua.LNumber(msg.Rcode))
			case "recursion_desired":
				L.Push(lua.LBool(msg.RecursionDesired))
			case "recursion_available":
				L.Push(lua.LBool(msg.RecursionAvailable))
			case "authenticated_data":
				L.Push(lua.LBool(msg.AuthenticatedData))
			case "answer":
				L.Push(rrSliceToTable(L, msg.Answer))
			case "ns":
				L.Push(rrSliceToTable(L, msg.Ns))
			case "extra":
				L.Push(rrSliceToTable(L, msg.Extra))
			case "set_reply":
				L.Push(L.NewFunction(
					method(func(L *lua.LState, msg *dns.Msg) int {
						request, ok := getUserDataArg[*dns.Msg](L, 2)
						if !ok {
							return 0
						}
						msg.SetReply(request)
						lv := userDataWithMetatable(L, luaMessageMetatableName, msg)
						L.Push(lv)
						return 1
					})))
			case "set_question":
				L.Push(L.NewFunction(
					method(func(L *lua.LState, msg *dns.Msg) int {
						msg.SetQuestion(L.CheckString(2), uint16(L.CheckNumber(3)))
						lv := userDataWithMetatable(L, luaMessageMetatableName, msg)
						L.Push(lv)
						return 1
					})))
			case "is_edns0":
				L.Push(L.NewFunction(
					method(func(L *lua.LState, msg *dns.Msg) int {
						opt := msg.IsEdns0()
						if opt == nil {
							L.Push(lua.LNil)
							return 1
						}
						// TODO: Return an OPT metatable name here, not generic RR
						lv := userDataWithMetatable(L, luaRRHeaderMetatableName, opt)
						L.Push(lv)
						return 1
					})))
			case "set_edns0":
				L.Push(L.NewFunction(
					method(func(L *lua.LState, msg *dns.Msg) int {
						msg.SetEdns0(uint16(L.CheckNumber(2)), L.CheckBool(3))
						lv := userDataWithMetatable(L, luaMessageMetatableName, msg)
						L.Push(lv)
						return 1
					})))
			default:
				L.ArgError(2, fmt.Sprintf("message does not have field %q", fieldName))
				return 0
			}
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			msg, ok := getUserDataArg[*dns.Msg](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "questions":
				table := L.CheckTable(3)
				n := table.Len()
				questions := make([]dns.Question, 0, n)
				for i := range n {
					element := table.RawGetInt(i + 1)
					if element.Type() != lua.LTUserData {
						L.ArgError(3, "invalid type, expected userdata")
						return 0
					}
					lq := element.(*lua.LUserData)
					q, ok := lq.Value.(*dns.Question)
					if !ok {
						L.ArgError(3, "invalid type, expected question")
						return 0
					}
					questions = append(questions, *q)
				}
				msg.Question = questions
			case "id":
				msg.Id = uint16(L.CheckInt(3))
			case "response":
				msg.Response = L.CheckBool(3)
			case "rcode":
				msg.Rcode = L.CheckInt(3)
			case "recursion_desired":
				msg.RecursionDesired = L.CheckBool(3)
			case "recursion_available":
				msg.RecursionAvailable = L.CheckBool(3)
			case "authenticated_data":
				msg.AuthenticatedData = L.CheckBool(3)
			case "answer":
				rrs, ok := tableToRRSlice(L, 3)
				if !ok {
					return 0
				}
				msg.Answer = rrs
			case "ns":
				rrs, ok := tableToRRSlice(L, 3)
				if !ok {
					return 0
				}
				msg.Ns = rrs
			case "extra":
				rrs, ok := tableToRRSlice(L, 3)
				if !ok {
					return 0
				}
				msg.Extra = rrs
			default:
				L.ArgError(2, fmt.Sprintf("message does not have field %q", fieldName))
				return 0
			}
			return 0
		}))
}

func rrSliceToTable(L *lua.LState, rrs []dns.RR) *lua.LTable {
	table := L.CreateTable(len(rrs), 0)
	for _, rr := range rrs {
		lv := userDataWithMetatable(L, luaRRHeaderMetatableName, rr)
		table.Append(lv)
	}
	return table
}

func tableToRRSlice(L *lua.LState, n int) ([]dns.RR, bool) {
	table := L.CheckTable(n)
	size := table.Len()
	rrs := make([]dns.RR, 0, size)
	for i := range size {
		element := table.RawGetInt(i + 1)
		if element.Type() != lua.LTUserData {
			L.ArgError(n, "invalid type, expected RR userdata")
			return nil, false
		}
		ud := element.(*lua.LUserData)
		rr, ok := ud.Value.(dns.RR)
		if !ok {
			L.ArgError(n, fmt.Sprintf("invalid type, expected RR, got %T", ud.Value))
			return nil, false
		}
		rrs = append(rrs, rr)
	}
	return rrs, true
}
