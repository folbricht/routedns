//go:build !nolua

package rdns

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

type ByteCode struct {
	*lua.FunctionProto
}

type LuaScript struct {
	L *lua.LState

	// How long the state may run before it is cut off. See LuaOptions.
	timeout time.Duration
}

// LuaCompile compiles lua script into bytecode. The returned bytecode can be used
// to instantiate one or more scripts.
func LuaCompile(reader io.Reader, name string) (ByteCode, error) {
	chunk, err := parse.Parse(reader, name)
	if err != nil {
		return ByteCode{}, err
	}
	proto, err := lua.Compile(chunk, name)
	if err != nil {
		return ByteCode{}, err
	}
	return ByteCode{proto}, nil
}

// NewScriptFromByteCode creates a new lua script from bytecode. When sandbox
// is true, only safe libraries are loaded (no io, os, debug, package, channel).
// The timeout bounds the top level of the script as well as every later call,
// so a script that never returns fails to load rather than hanging startup.
func NewScriptFromByteCode(b ByteCode, sandbox bool, timeout time.Duration) (*LuaScript, error) {
	var L *lua.LState
	if sandbox {
		L = lua.NewState(lua.Options{SkipOpenLibs: true})
		openSandboxedLibs(L)
	} else {
		L = lua.NewState()
	}
	s := &LuaScript{L: L, timeout: timeout}
	lfunc := L.NewFunctionFromProto(b.FunctionProto)
	L.Push(lfunc)
	return s, s.bounded(func() error { return L.PCall(0, lua.MultRet, nil) })
}

// bounded runs fn with the state limited to the script's timeout. The
// interpreter checks for cancellation between instructions, so a loop with no
// exit is cut off rather than holding its instance for the life of the process.
// Time spent inside a Go call, an upstream resolver above all, is not
// interrupted but does count towards the limit.
//
// The state is usable again afterwards, which is what lets the instance go back
// into the pool rather than being thrown away.
func (s *LuaScript) bounded(fn func() error) error {
	if s.timeout <= 0 {
		return fn()
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	s.L.SetContext(ctx)
	defer s.L.RemoveContext()
	return fn()
}

// openSandboxedLibs opens only safe Lua libraries and removes dangerous base functions.
func openSandboxedLibs(L *lua.LState) {
	// Open safe libraries
	for _, lib := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
		{lua.CoroutineLibName, lua.OpenCoroutine},
	} {
		L.Push(L.NewFunction(lib.fn))
		L.Push(lua.LString(lib.name))
		L.Call(1, 0)
	}

	// Remove dangerous base functions
	for _, name := range []string{"dofile", "loadfile", "load", "loadstring", "module", "require"} {
		L.SetGlobal(name, lua.LNil)
	}
}

func (s *LuaScript) HasFunction(name string) bool {
	return s.L.GetGlobal(name).Type() == lua.LTFunction
}

func (s *LuaScript) Call(fnName string, nret int, params ...any) ([]any, error) {
	args := []lua.LValue{
		userDataWithMetatable(s.L, luaMessageMetatableName, params[0]),
		userDataWithMetatable(s.L, luaClientInfoMetatableName, params[1]),
	}

	// Call the resolve() function in the lua script
	if err := s.bounded(func() error {
		return s.L.CallByParam(lua.P{
			Fn:      s.L.GetGlobal(fnName),
			NRet:    nret,
			Protect: true,
		}, args...)
	}); err != nil {
		return nil, fmt.Errorf("failed to call lua: %w", err)
	}

	// Grab return values from the stack and add them to the result slice
	// in reverse order
	ret := make([]any, nret)
	for i := range slices.Backward(ret) {
		lv := s.L.Get(-1)
		s.L.Pop(1)

		var v any

		switch lv.Type() {
		case lua.LTNil:
			v = nil
		case lua.LTUserData:
			ud := lv.(*lua.LUserData)
			v = ud.Value
		case lua.LTString:
			v = lv.String()
		default:
			return nil, fmt.Errorf("unsupported return type: %v", lv.Type())
		}
		ret[i] = v
	}

	return ret, nil
}
