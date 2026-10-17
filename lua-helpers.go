//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"fmt"
	"reflect"

	lua "github.com/folbricht/glua"
)

// Helper functions

// luaArray reads the elements of a Lua array, each converted to T.
func luaArray[T any](v lua.Value) ([]T, error) {
	var table *lua.Table
	if v.Kind() == lua.KindTable {
		table, _ = v.As[*lua.Table]()
	}
	if table == nil {
		return nil, fmt.Errorf("expected array, got %v", v.Kind())
	}
	values := make([]T, 0, table.Len())
	for i := range table.Len() {
		element, err := table.Get(lua.Int(int64(i + 1))).As[T]()
		if err != nil {
			return nil, fmt.Errorf("invalid type, expected %v", reflect.TypeFor[T]())
		}
		values = append(values, element)
	}
	return values, nil
}

// luaTable makes a Lua array of values, each converted by fn.
func luaTable[T any](values []T, fn func(T) lua.Value) *lua.Table {
	table := lua.NewTable(len(values), 0)
	for i, v := range values {
		table.Set(lua.Int(int64(i+1)), fn(v))
	}
	return table
}

type numbers interface {
	int | int8 | int16 | int32 | int64 | float32 | float64 | uint | uint8 | uint16 | uint32 | uint64
}

func numberSliceToTable[T numbers](values []T) *lua.Table {
	return luaTable(values, func(v T) lua.Value { return lua.Int(int64(v)) })
}
