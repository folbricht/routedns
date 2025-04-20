package rdns

import (
	"errors"

	lua "github.com/yuin/gopher-lua"
)

// Error functions

func (s *LuaScript) RegisterErrorType() {
	L := s.L
	mt := L.NewTypeMetatable(luaErrorTypeName)
	L.SetGlobal("Error", mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(newError))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"error": getter(errorGetError),
	}))
}

func newError(L *lua.LState) int {
	err := errors.New(L.CheckString(1))
	L.Push(userDataWithType(L, luaErrorTypeName, err))
	return 1
}
func errorGetError(L *lua.LState, r error) { L.Push(lua.LString(r.Error())) }
