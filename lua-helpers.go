package rdns

import (
	"fmt"
	"reflect"

	lua "github.com/yuin/gopher-lua"
)

// Helper functions

func getter[T any](f func(*lua.LState, T)) func(*lua.LState) int {
	return func(L *lua.LState) int {
		if L.GetTop() > 1 {
			L.ArgError(1, "no arguments expected")
			return 0
		}
		ud := L.CheckUserData(1)
		r, ok := ud.Value.(T)
		if !ok {
			L.ArgError(1, fmt.Sprintf("%v expected", reflect.TypeFor[T]()))
			return 0
		}
		f(L, r)
		return 1
	}
}
func setter[T any](f func(*lua.LState, T)) func(*lua.LState) int {
	return func(L *lua.LState) int {
		if L.GetTop() < 2 {
			L.ArgError(1, "expected at least 1 argument")
			return 0
		}
		ud := L.CheckUserData(1)
		r, ok := ud.Value.(T)
		if !ok {
			L.ArgError(1, fmt.Sprintf("%v expected", reflect.TypeFor[T]()))
			return 0
		}
		f(L, r)
		return 1
	}
}
