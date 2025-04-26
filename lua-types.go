package rdns

import lua "github.com/yuin/gopher-lua"

func userDataWithMetatable(L *lua.LState, mtName string, value any) *lua.LUserData {
	ud := L.NewUserData()
	ud.Value = value
	L.SetMetatable(ud, L.GetTypeMetatable(mtName))
	return ud
}
