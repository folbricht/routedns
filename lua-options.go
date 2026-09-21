package rdns

// LuaOptions holds the settings for the Lua resolver. It is built with or
// without the "nolua" tag, which leaves out the Lua interpreter, so that the
// config layer in cmd/routedns compiles either way.
type LuaOptions struct {
	Script      string
	Concurrency uint
	NoSandbox   bool // Disables the sandbox. When false (default), scripts cannot access os/io/debug/etc.
}
