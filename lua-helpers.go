package rdns

import (
	"fmt"
	"reflect"

	lua "github.com/yuin/gopher-lua"
)

// Helper functions

func method[T any](f func(*lua.LState, T) int) func(*lua.LState) int {
	return func(L *lua.LState) int {
		if L.GetTop() < 1 {
			L.ArgError(1, "expected at least 1 argument")
			return 0
		}
		ud := L.CheckUserData(1)
		r, ok := ud.Value.(T)
		if !ok {
			L.ArgError(1, fmt.Sprintf("%v expected", reflect.TypeFor[T]()))
			return 0
		}
		return f(L, r)
	}
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

type numbers interface {
	int | int8 | int16 | int32 | int64 | float32 | float64 | uint | uint8 | uint16 | uint32 | uint64
}

func getNumberSlice[T numbers](L *lua.LState, n int) ([]T, bool) {
	table := L.CheckTable(n)
	size := table.Len()
	values := make([]T, 0, size)
	for i := range size {
		element := table.RawGetInt(i + 1)
		if element.Type() != lua.LTNumber {
			L.ArgError(n, "invalid type, expected number")
			return nil, false
		}
		value := T(element.(lua.LNumber))
		values = append(values, value)
	}
	return values, true
}

func numberSliceToTable[T numbers](L *lua.LState, values []T) *lua.LTable {
	table := L.CreateTable(len(values), 0)
	for _, value := range values {
		table.Append(lua.LNumber(value))
	}
	L.Push(table)
	return table
}
