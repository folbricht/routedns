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

type LuaOptions struct {
	Script      string
	Concurrency uint
}

func NewLua(id string, opt LuaOptions, resolvers ...Resolver) (*Lua, error) {
	if opt.Concurrency == 0 {
		opt.Concurrency = 4
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

	// Call the "resolve" function in the script. It should return 2 values.
	ret, err := s.Call("resolve", 2, q, ci)
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

	return answer, err
}

func (r *Lua) String() string {
	return r.id
}

func (r *Lua) newScript() (*LuaScript, error) {
	s, err := NewScriptFromByteCode(r.bytecode)
	if err != nil {
		return nil, err
	}

	// Register types and methods
	s.RegisterMessageType()
	s.RegisterQuestionType()
	s.RegisterErrorType()

	// Inject the resolvers into the state (so they can be used in the script)
	s.InjectResolvers(r.resolvers)

	// The script must contain a resolve() function which is the entry point
	if !s.HasFunction("resolve") {
		return nil, errors.New("no resolve() function found in lua script")
	}

	return s, nil
}
