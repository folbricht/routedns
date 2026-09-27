//go:build !nolua

package rdns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type Lua struct {
	id        string
	resolvers []Resolver
	scripts   chan *LuaScript
	bytecode  ByteCode

	opt LuaOptions
}

var _ Resolver = &Lua{}

func NewLua(id string, opt LuaOptions, resolvers ...Resolver) (*Lua, error) {
	if opt.Concurrency == 0 {
		opt.Concurrency = 4
	}
	if opt.Timeout == 0 {
		opt.Timeout = defaultLuaTimeout
	}

	// Compile the script
	bytecode, err := LuaCompile(strings.NewReader(opt.Script), id)
	if err != nil {
		return nil, err
	}

	r := &Lua{
		id:        id,
		resolvers: resolvers,
		opt:       opt,
		scripts:   make(chan *LuaScript, opt.Concurrency),
		bytecode:  bytecode,
	}

	// Initialize scripts
	for range opt.Concurrency {
		s, err := r.newScript()
		if err != nil {
			return nil, err
		}
		r.scripts <- s
	}
	return r, nil
}

func (r *Lua) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	s := <-r.scripts
	defer func() { r.scripts <- s }()

	log := logger(r.id, q, ci)

	// The script is handed the query to read, to pass on and to change as it
	// sees fit, which it may not do to the caller's message. Copy it, which is
	// nothing next to running a script.
	q = q.Copy()

	// Call the "resolve" function in the script. It should return 2 values.
	ret, err := s.Call("Resolve", 2, q, ci)
	if err != nil {
		log.Error("failed to run lua script", "error", err)
		return nil, err
	}

	// Extract the answer and error from the returned values
	if len(ret) != 2 {
		return nil, fmt.Errorf("invalid return value, expected 2, got %d", len(ret))
	}

	answer, ok := ret[0].(*dns.Msg)
	if ret[0] != nil && !ok {
		return nil, fmt.Errorf("invalid return value, expected Message, got %T", ret[0])
	}

	err, ok = ret[1].(error)
	if ret[1] != nil && !ok {
		return nil, fmt.Errorf("invalid return value, expected Error, got %T", ret[1])
	}

	// Copy the answer on the way out for the reason the query was copied on the
	// way in, and one more. The state is handed back to the pool as this
	// returns, while the caller is still reading what it was given: a listener
	// truncates, pads and packs the answer after the call. A script can keep
	// anything it was handed, in a global, an upvalue or a table, since the
	// state lasts as long as the process, so a script holding on to an answer
	// would be able to write to it from the next query to reach that state.
	if answer != nil {
		answer = answer.Copy()
	}

	return answer, err
}

func (r *Lua) String() string {
	return r.id
}

func (r *Lua) Close() {
	close(r.scripts)
	for s := range r.scripts {
		s.L.Close()
	}
}

func (r *Lua) newScript() (*LuaScript, error) {
	s, err := NewScriptFromByteCode(r.bytecode, !r.opt.NoSandbox, r.opt.Timeout)
	if err != nil {
		return nil, err
	}

	// Register types and methods
	s.RegisterConstants()
	s.RegisterMessageType()
	s.RegisterQuestionType()
	s.RegisterRRTypes()
	s.RegisterOPTType()
	s.RegisterEDNS0Types()
	s.RegisterErrorType()
	s.RegisterClientInfoType()

	// Inject the resolvers into the state (so they can be used in the script)
	s.InjectResolvers(r.resolvers)

	// The script must contain a Resolve() function which is the entry point
	if !s.HasFunction("Resolve") {
		return nil, errors.New("no Resolve() function found in lua script")
	}

	return s, nil
}
