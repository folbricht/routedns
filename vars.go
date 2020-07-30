package rdns

import (
	"expvar"
	"fmt"
)

type varInt = expvar.Int
type varMap = expvar.Map

func getVarInt(base string, id string, name string) *varInt {
	fullname := fmt.Sprintf("routedns.%s.%s.%s", base, id, name)
	if v := expvar.Get(fullname); v != nil {
		return v.(*expvar.Int)
	}
	return expvar.NewInt(fullname)
}

func getVarMap(base string, id string, name string) *varMap {
	fullname := fmt.Sprintf("routedns.%s.%s.%s", base, id, name)
	if v := expvar.Get(fullname); v != nil {
		return v.(*expvar.Map)
	}
	return expvar.NewMap(fullname)
}
