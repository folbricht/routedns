package rdns

import (
	"fmt"
	"reflect"

	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// Resolver functions

const luaResolverMetatableName = "Resolver"

func (s *LuaScript) InjectResolvers(resolvers []Resolver) {
	L := s.L
	mt := L.NewTypeMetatable(luaResolverMetatableName)
	L.SetGlobal("Resolver", mt)

	// Methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"resolve": resolverResolve,
	}))

	table := L.CreateTable(len(resolvers), 0)
	for _, r := range resolvers {
		lv := userDataWithMetatable(L, luaResolverMetatableName, r)
		table.Append(lv)
	}
	L.SetGlobal("Resolvers", table)
}

func resolverResolve(L *lua.LState) int {
	if L.GetTop() != 3 {
		L.ArgError(1, "expected 2 arguments")
		return 0
	}
	r, ok := getUserDataArg[Resolver](L, 1)
	if !ok {
		return 0
	}
	msg, ok := getUserDataArg[*dns.Msg](L, 2)
	if !ok {
		return 0
	}
	ci, ok := getUserDataArg[ClientInfo](L, 3)
	if !ok {
		return 0
	}

	resp, err := r.Resolve(msg, ci)

	// Return the answer
	L.Push(userDataWithMetatable(L, luaMessageMetatableName, resp))

	// Return the error
	if err != nil {
		L.Push(userDataWithMetatable(L, luaErrorMetatableName, err))
	} else {
		L.Push(lua.LNil)
	}

	return 2
}

func getUserDataArg[T any](L *lua.LState, n int) (T, bool) {
	ud := L.CheckUserData(n)
	v, ok := ud.Value.(T)
	if !ok {
		L.ArgError(n, fmt.Sprintf("expected %v, got %T", reflect.TypeFor[T](), ud.Value))
		return v, false
	}
	return v, true
}
