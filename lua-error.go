package rdns

import (
	"errors"

	lua "github.com/yuin/gopher-lua"
)

// Error functions

const luaErrorMetatableName = "Error"

func (s *LuaScript) RegisterErrorType() {
	L := s.L
	mt := L.NewTypeMetatable(luaErrorMetatableName)
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
	L.Push(userDataWithMetatable(L, luaErrorMetatableName, err))
	return 1
}

func errorGetError(L *lua.LState, r error) { L.Push(lua.LString(r.Error())) }
