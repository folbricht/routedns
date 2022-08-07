package rdns

import (
	"expvar"
	"fmt"
)

// Get an *expvar.Int with the given path.
func getVarInt(base string, id string, name string) *expvar.Int {
	fullname := fmt.Sprintf("routedns.%s.%s.%s", base, id, name)
	if v := expvar.Get(fullname); v != nil {
		return v.(*expvar.Int)
	}
	return expvar.NewInt(fullname)
}

// Get an *expvar.Map with the given path.
func getVarMap(base string, id string, name string) *expvar.Map {
	fullname := fmt.Sprintf("routedns.%s.%s.%s", base, id, name)
	if v := expvar.Get(fullname); v != nil {
		return v.(*expvar.Map)
	}
	return expvar.NewMap(fullname)
}

// Get an *expvar.Map with the given path.
func getVarString(base string, id string, name string) *expvar.String {
	fullname := fmt.Sprintf("routedns.%s.%s.%s", base, id, name)
	if v := expvar.Get(fullname); v != nil {
		return v.(*expvar.String)
	}
	return expvar.NewString(fullname)
}
