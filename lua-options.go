package rdns

import "time"

// LuaOptions holds the settings for the Lua resolver. It is built with or
// without the Lua interpreter, which the "nolua" tag and 32-bit platforms
// leave out, so that the config layer in cmd/routedns compiles either way.
type LuaOptions struct {
	Script    string
	NoSandbox bool // Disables the sandbox. When false (default), scripts cannot access os/io or load code.

	// How long a script may run, both for a query and for the top level when
	// the script is loaded. Zero applies defaultLuaTimeout; negative removes
	// the limit, leaving only the interpreter's step and allocation limits.
	Timeout time.Duration
}

// How long a script may run when nothing else is configured. Generous enough
// that no script doing real work reaches it, including one waiting on upstream
// resolvers, while still bounding one that never returns at all.
const defaultLuaTimeout = 30 * time.Second
