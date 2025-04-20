package rdns

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

type Lua struct {
	id        string
	resolvers []Resolver
	states    chan *lua.LState

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
	r := &Lua{
		id:        id,
		resolvers: resolvers,
		opt:       opt,
		states:    make(chan *lua.LState, opt.Concurrency),
	}

	// Initialize lua states
	for range opt.Concurrency {
		L, err := r.newState()
		if err != nil {
			return nil, err
		}
		r.states <- L
	}
	return r, nil
}

func (r *Lua) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	L := <-r.states
	defer func() { r.states <- L }()

	log := logger(r.id, q, ci)

	lq := userDataWithType(L, luaMessageTypeName, q)
	lci := L.NewUserData()
	lci.Value = ci

	// Call the resolve() function in the lua script
	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("resolve"),
		NRet:    2,
		Protect: true,
	}, lq, lci); err != nil {
		log.Error("failed to run lua script", "error", err)
		return nil, fmt.Errorf("failed to run lua script: %w", err)
	}

	// Grab return values from the stack
	lanswer := L.Get(-2)
	lerr := L.Get(-1)
	L.Pop(2)

	// Check for errors
	switch lerr.Type() {
	case lua.LTNil: // No error
	case lua.LTUserData:
		ud := lerr.(*lua.LUserData)
		err, ok := ud.Value.(error)
		if !ok {
			err := fmt.Errorf("invalid respone type from lua script, expected error, got %T", ud.Value)
			log.Error("failed to run lua script", "error", err)
			return nil, err
		}
		return nil, err

	default:
		err := fmt.Errorf("invalid respone type from lua script, expected userdata, got %T", lerr)
		log.Error("failed to run lua script", "error", err)
		return nil, err
	}

	// Check the response
	switch lanswer.Type() {
	case lua.LTNil:
		return nil, nil

	case lua.LTUserData:
		ud := lanswer.(*lua.LUserData)
		msg, ok := ud.Value.(*dns.Msg)
		if !ok {
			err := fmt.Errorf("invalid respone type from lua script, expected Message, got %T", ud.Value)
			log.Error("failed to run lua script", "error", err)
			return nil, err
		}
		return msg, nil

	default:
		err := fmt.Errorf("invalid respone type from lua script, expected userdata, got %T", lerr)
		log.Error("failed to run lua script", "error", err)
		return nil, err
	}
}

func (r *Lua) String() string {
	return r.id
}

func (r *Lua) newState() (*lua.LState, error) {
	L := lua.NewState()

	// Register types
	registerMessageType(L)
	registerQuestionType(L)
	registerErrorType(L)

	// Inject the resolvers into the state (so they can be used in the script)
	registerResolvers(L, r.resolvers)

	if err := L.DoString(r.opt.Script); err != nil {
		return nil, err
	}

	// The script must contain a resolve() function which is the entry point
	if resolveFunc := L.GetGlobal("resolve"); resolveFunc.Type() != lua.LTFunction {
		return nil, errors.New("no resolve() function found in lua script")
	}

	return L, nil
}

// Define Lua types
const (
	luaResolverTypeName = "Resolver"
	luaMessageTypeName  = "Message"
	luaQuestionTypeName = "Question"
	luaErrorTypeName    = "Error"
)

// Resolver functions

func registerResolvers(L *lua.LState, resolvers []Resolver) {
	mt := L.NewTypeMetatable(luaResolverTypeName)
	L.SetGlobal("Resolver", mt)

	// Methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"resolve": resolverResolve,
	}))

	table := L.CreateTable(len(resolvers), 0)
	for _, r := range resolvers {
		lv := userDataWithType(L, luaResolverTypeName, r)
		table.Append(lv)
	}
	L.SetGlobal("Resolvers", table)
}

func resolverResolve(L *lua.LState) int {
	if L.GetTop() != 3 {
		L.ArgError(1, "expected at 2 argument")
		return 0
	}
	r, ok := getUserDataArg[Resolver](L, 1)
	if !ok {
		return 0
	}
	msg, ok := getUserDataArg[*dns.Msg](L, 2)
	if !ok {
		return 0
	}
	ci, ok := getUserDataArg[ClientInfo](L, 3)
	if !ok {
		return 0
	}

	resp, err := r.Resolve(msg, ci)

	// Return the answer
	L.Push(userDataWithType(L, luaMessageTypeName, resp))

	// Return the error
	if err != nil {
		L.Push(userDataWithType(L, luaErrorTypeName, err))
	} else {
		L.Push(lua.LNil)
	}

	return 2
}

func getUserDataArg[T any](L *lua.LState, n int) (T, bool) {
	ud := L.CheckUserData(n)
	v, ok := ud.Value.(T)
	if !ok {
		L.ArgError(n, fmt.Sprintf("expected %v, got %T", reflect.TypeFor[T](), ud.Value))
		return v, false
	}
	return v, true
}

// Message functions

func registerMessageType(L *lua.LState) {
	mt := L.NewTypeMetatable(luaMessageTypeName)
	L.SetGlobal("Message", mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(newMessage))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get_question": getter(messageGetQuestion),
		"set_question": setter(messageSetQuestion),
	}))
}

func newMessage(L *lua.LState) int {
	L.Push(userDataWithType(L, luaMessageTypeName, new(dns.Msg)))
	return 1
}

func messageGetQuestion(L *lua.LState, msg *dns.Msg) {
	table := L.CreateTable(len(msg.Question), 0)
	for _, q := range msg.Question {
		lv := userDataWithType(L, luaQuestionTypeName, &q)
		table.Append(lv)
	}
	L.Push(table)
}

func messageSetQuestion(L *lua.LState, msg *dns.Msg) {
	table := L.CheckTable(2)
	n := table.Len()
	questions := make([]dns.Question, 0, n)
	for i := range n {
		element := table.RawGetInt(i + 1)
		if element.Type() != lua.LTUserData {
			L.ArgError(1, "invalid type, expected userdata")
			return
		}
		lq := element.(*lua.LUserData)
		q, ok := lq.Value.(*dns.Question)
		if !ok {
			L.ArgError(1, "invalid type, expected question")
			return
		}
		questions = append(questions, *q)
	}
	msg.Question = questions
}

// Question functions

func registerQuestionType(L *lua.LState) {
	mt := L.NewTypeMetatable(luaQuestionTypeName)
	L.SetGlobal("Question", mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(newQuestion))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"get_name":   getter(questionGetName),
		"get_qtype":  getter(questionGetQType),
		"get_qclass": getter(questionGetQClass),
		"set_name":   setter(questionSetName),
		"set_qtype":  setter(questionSetQType),
		"set_qclass": setter(questionSetQClass),
	}))
}

func newQuestion(L *lua.LState) int {
	L.Push(userDataWithType(L, luaQuestionTypeName, new(dns.Question)))
	return 1
}

func questionGetName(L *lua.LState, r *dns.Question)   { L.Push(lua.LString(r.Name)) }
func questionGetQType(L *lua.LState, r *dns.Question)  { L.Push(lua.LNumber(r.Qtype)) }
func questionGetQClass(L *lua.LState, r *dns.Question) { L.Push(lua.LNumber(r.Qclass)) }

func questionSetName(L *lua.LState, r *dns.Question)   { r.Name = L.CheckString(2) }
func questionSetQType(L *lua.LState, r *dns.Question)  { r.Qtype = uint16(L.CheckInt(2)) }
func questionSetQClass(L *lua.LState, r *dns.Question) { r.Qclass = uint16(L.CheckInt(2)) }

// Error functions

func registerErrorType(L *lua.LState) {
	mt := L.NewTypeMetatable(luaErrorTypeName)
	L.SetGlobal("Error", mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(newError))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"error": getter(errorGetError),
	}))
}

func newError(L *lua.LState) int {
	err := errors.New(L.CheckString(1))
	L.Push(userDataWithType(L, luaErrorTypeName, err))
	return 1
}
func errorGetError(L *lua.LState, r error) { L.Push(lua.LString(r.Error())) }

// Helper functions

func userDataWithType(L *lua.LState, typ string, value any) *lua.LUserData {
	ud := L.NewUserData()
	ud.Value = value
	L.SetMetatable(ud, L.GetTypeMetatable(typ))
	return ud
}

func getter[T any](f func(*lua.LState, T)) func(*lua.LState) int {
	return func(L *lua.LState) int {
		if L.GetTop() > 1 {
			L.ArgError(1, "no arguments expected")
			return 0
		}
		ud := L.CheckUserData(1)
		r, ok := ud.Value.(T)
		if !ok {
			L.ArgError(1, fmt.Sprintf("%v expected", reflect.TypeFor[T]()))
			return 0
		}
		f(L, r)
		return 1
	}
}
func setter[T any](f func(*lua.LState, T)) func(*lua.LState) int {
	return func(L *lua.LState) int {
		if L.GetTop() < 2 {
			L.ArgError(1, "expected at least 1 argument")
			return 0
		}
		ud := L.CheckUserData(1)
		r, ok := ud.Value.(T)
		if !ok {
			L.ArgError(1, fmt.Sprintf("%v expected", reflect.TypeFor[T]()))
			return 0
		}
		f(L, r)
		return 1
	}
}
