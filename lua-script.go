//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"os"
	"slices"

	lua "github.com/folbricht/glua"
)

// newLuaRuntime makes the runtime a lua group loads its script into, with the
// DNS types and constants and the group's resolvers. When sandbox is true,
// only safe libraries are loaded, with no access to files, the operating
// system or loading code at run time.
func newLuaRuntime(sandbox bool, resolvers []Resolver) (*lua.Runtime, error) {
	db, err := loadRRDB()
	if err != nil {
		return nil, err
	}
	libs := lua.LibSafe | lua.LibCoroutine
	if !sandbox {
		libs |= lua.LibOS | lua.LibIO | lua.LibLoad
	}
	opts := slices.Concat(
		[]lua.Option{
			libs,
			lua.Output(os.Stdout),
			// Only the types registered here are visible to scripts
			lua.AutoBind(false),
		},
		luaConstants(),
		luaMessageType(),
		luaQuestionType(),
		luaRRType(db),
		luaOPTType(),
		luaEDNS0Types(),
		luaErrorType(),
		luaClientInfoType(),
		luaResolverTypes(resolvers),
	)
	return lua.New(opts...)
}
