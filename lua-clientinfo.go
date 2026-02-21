package rdns

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

const luaClientInfoMetatableName = "ClientInfo"

func (s *LuaScript) RegisterClientInfoType() {
	L := s.L
	mt := L.NewTypeMetatable(luaClientInfoMetatableName)
	L.SetGlobal(luaClientInfoMetatableName, mt)
	// methods and fields
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			ci, ok := getUserDataArg[ClientInfo](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			switch fieldName {
			case "source_ip":
				if ci.SourceIP != nil {
					L.Push(lua.LString(ci.SourceIP.String()))
				} else {
					L.Push(lua.LNil)
				}
			case "doh_path":
				L.Push(lua.LString(ci.DoHPath))
			case "tls_server_name":
				L.Push(lua.LString(ci.TLSServerName))
			case "listener":
				L.Push(lua.LString(ci.Listener))
			default:
				L.ArgError(2, fmt.Sprintf("clientinfo does not have field %q", fieldName))
				return 0
			}
			return 1
		}))
}
