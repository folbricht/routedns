package rdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// EDNS0 functions

// RegisterEDNS0Types makes the supported EDNS0 options available to scripts,
// each as a global type with a "new" constructor and named fields.
//
// A type is described by the value its constructor builds and its fields, in
// the order "new" takes them as arguments. Every field can also be read and
// written by name, alongside "option" which gives the option code.
func (s *LuaScript) RegisterEDNS0Types() {
	registerEDNS0Type(s, "EDNS0_COOKIE",
		func() *dns.EDNS0_COOKIE { return &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE} },
		stringField("cookie", func(e *dns.EDNS0_COOKIE) *string { return &e.Cookie }),
	)
	registerEDNS0Type(s, "EDNS0_DAU",
		func() *dns.EDNS0_DAU { return &dns.EDNS0_DAU{Code: dns.EDNS0DAU} },
		numberSliceField("algcode", func(e *dns.EDNS0_DAU) *[]uint8 { return &e.AlgCode }),
	)
	registerEDNS0Type(s, "EDNS0_DHU",
		func() *dns.EDNS0_DHU { return &dns.EDNS0_DHU{Code: dns.EDNS0DHU} },
		numberSliceField("algcode", func(e *dns.EDNS0_DHU) *[]uint8 { return &e.AlgCode }),
	)
	registerEDNS0Type(s, "EDNS0_EDE",
		func() *dns.EDNS0_EDE { return new(dns.EDNS0_EDE) },
		numberField("infocode", func(e *dns.EDNS0_EDE) *uint16 { return &e.InfoCode }),
		stringField("extratext", func(e *dns.EDNS0_EDE) *string { return &e.ExtraText }),
	)
	registerEDNS0Type(s, "EDNS0_ESU",
		func() *dns.EDNS0_ESU { return &dns.EDNS0_ESU{Code: dns.EDNS0ESU} },
		stringField("uri", func(e *dns.EDNS0_ESU) *string { return &e.Uri }),
	)
	registerEDNS0Type(s, "EDNS0_EXPIRE",
		func() *dns.EDNS0_EXPIRE { return &dns.EDNS0_EXPIRE{Code: dns.EDNS0EXPIRE} },
		numberField("expire", func(e *dns.EDNS0_EXPIRE) *uint32 { return &e.Expire }),
	)
	registerEDNS0Type(s, "EDNS0_LLQ",
		func() *dns.EDNS0_LLQ { return &dns.EDNS0_LLQ{Code: dns.EDNS0LLQ} },
		numberField("version", func(e *dns.EDNS0_LLQ) *uint16 { return &e.Version }),
		numberField("opcode", func(e *dns.EDNS0_LLQ) *uint16 { return &e.Opcode }),
		numberField("error", func(e *dns.EDNS0_LLQ) *uint16 { return &e.Error }),
		numberField("id", func(e *dns.EDNS0_LLQ) *uint64 { return &e.Id }),
		numberField("leaselife", func(e *dns.EDNS0_LLQ) *uint32 { return &e.LeaseLife }),
	)
	registerEDNS0Type(s, "EDNS0_LOCAL",
		func() *dns.EDNS0_LOCAL { return new(dns.EDNS0_LOCAL) },
		numberField("code", func(e *dns.EDNS0_LOCAL) *uint16 { return &e.Code }),
		bytesField("data", func(e *dns.EDNS0_LOCAL) *[]byte { return &e.Data }),
	)
	registerEDNS0Type(s, "EDNS0_N3U",
		func() *dns.EDNS0_N3U { return &dns.EDNS0_N3U{Code: dns.EDNS0N3U} },
		numberSliceField("algcode", func(e *dns.EDNS0_N3U) *[]uint8 { return &e.AlgCode }),
	)
	registerEDNS0Type(s, "EDNS0_NSID",
		func() *dns.EDNS0_NSID { return &dns.EDNS0_NSID{Code: dns.EDNS0NSID} },
		stringField("nsid", func(e *dns.EDNS0_NSID) *string { return &e.Nsid }),
	)
	registerEDNS0Type(s, "EDNS0_PADDING",
		func() *dns.EDNS0_PADDING { return new(dns.EDNS0_PADDING) },
		bytesField("padding", func(e *dns.EDNS0_PADDING) *[]byte { return &e.Padding }),
	)
	registerEDNS0Type(s, "EDNS0_SUBNET",
		func() *dns.EDNS0_SUBNET { return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET} },
		numberField("family", func(e *dns.EDNS0_SUBNET) *uint16 { return &e.Family }),
		numberField("sourcenetmask", func(e *dns.EDNS0_SUBNET) *uint8 { return &e.SourceNetmask }),
		numberField("sourcescope", func(e *dns.EDNS0_SUBNET) *uint8 { return &e.SourceScope }),
		ipField("address", func(e *dns.EDNS0_SUBNET) *net.IP { return &e.Address }),
	)
	registerEDNS0Type(s, "EDNS0_TCP_KEEPALIVE",
		func() *dns.EDNS0_TCP_KEEPALIVE {
			return &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE}
		},
		numberField("timeout", func(e *dns.EDNS0_TCP_KEEPALIVE) *uint16 { return &e.Timeout }),
	)
	registerEDNS0Type(s, "EDNS0_UL",
		func() *dns.EDNS0_UL { return &dns.EDNS0_UL{Code: dns.EDNS0UL} },
		numberField("lease", func(e *dns.EDNS0_UL) *uint32 { return &e.Lease }),
		numberField("keylease", func(e *dns.EDNS0_UL) *uint32 { return &e.KeyLease }),
	)
}

// edns0Field is one named field of an EDNS0 option type as scripts see it. The
// setter takes the stack index to read the value from, which is the argument
// position in a constructor call and always 3 in an assignment.
type edns0Field[T dns.EDNS0] struct {
	name string
	get  func(L *lua.LState, e T) lua.LValue
	set  func(L *lua.LState, e T, n int)
}

// Registers a global Lua type for one EDNS0 option: a "new" constructor taking
// the fields as positional arguments, all of them optional, and metamethods to
// read and write them by name.
func registerEDNS0Type[T dns.EDNS0](s *LuaScript, mtName string, newOption func() T, fields ...edns0Field[T]) {
	L := s.L
	mt := L.NewTypeMetatable(mtName)
	L.SetGlobal(mtName, mt)

	byName := make(map[string]edns0Field[T], len(fields))
	for _, field := range fields {
		byName[field.name] = field
	}
	// Reports the field being read or written, having raised a Lua error if
	// the type doesn't have it. ArgError does not return.
	lookup := func(L *lua.LState) (edns0Field[T], bool) {
		fieldName := L.CheckString(2)
		field, ok := byName[fieldName]
		if !ok {
			L.ArgError(2, fmt.Sprintf("%s does not have field %q", mtName, fieldName))
		}
		return field, ok
	}

	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			e := newOption()
			nArgs := L.GetTop()
			for i, field := range fields {
				if nArgs < i+1 {
					break
				}
				field.set(L, e, i+1)
			}
			L.Push(userDataWithMetatable(L, mtName, e))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[T](L, 1)
			if !ok {
				return 0
			}
			if L.CheckString(2) == "option" {
				L.Push(lua.LNumber(e.Option()))
				return 1
			}
			field, ok := lookup(L)
			if !ok {
				return 0
			}
			L.Push(field.get(L, e))
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			e, ok := getUserDataArg[T](L, 1)
			if !ok {
				return 0
			}
			field, ok := lookup(L)
			if !ok {
				return 0
			}
			field.set(L, e, 3)
			return 0
		}))
}

// A numeric field, converted between Lua numbers and the field's own width.
func numberField[T dns.EDNS0, V numbers](name string, field func(T) *V) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(L *lua.LState, e T) lua.LValue { return lua.LNumber(*field(e)) },
		set:  func(L *lua.LState, e T, n int) { *field(e) = V(L.CheckNumber(n)) },
	}
}

// A field of numbers, exposed as a Lua table.
func numberSliceField[T dns.EDNS0, V numbers](name string, field func(T) *[]V) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(L *lua.LState, e T) lua.LValue { return numberSliceToTable(L, *field(e)) },
		set: func(L *lua.LState, e T, n int) {
			values, _ := getNumberSlice[V](L, n)
			*field(e) = values
		},
	}
}

func stringField[T dns.EDNS0](name string, field func(T) *string) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(L *lua.LState, e T) lua.LValue { return lua.LString(*field(e)) },
		set:  func(L *lua.LState, e T, n int) { *field(e) = L.CheckString(n) },
	}
}

// A byte-slice field, exposed to scripts as a string.
func bytesField[T dns.EDNS0](name string, field func(T) *[]byte) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(L *lua.LState, e T) lua.LValue { return lua.LString(*field(e)) },
		set:  func(L *lua.LState, e T, n int) { *field(e) = []byte(L.CheckString(n)) },
	}
}

// An IP address field, exposed as a string and rejected if it doesn't parse.
func ipField[T dns.EDNS0](name string, field func(T) *net.IP) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(L *lua.LState, e T) lua.LValue { return lua.LString(field(e).String()) },
		set: func(L *lua.LState, e T, n int) {
			value := L.CheckString(n)
			ip := net.ParseIP(value)
			if ip == nil {
				L.ArgError(n, fmt.Sprintf("expected IP address, got %q", value))
				return
			}
			*field(e) = ip
		},
	}
}
