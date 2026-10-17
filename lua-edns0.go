//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"fmt"
	"net"
	"reflect"

	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

// EDNS0 functions

// luaEDNS0Kinds are the EDNS0 options available to scripts, each as a global
// type with a "new" constructor and named fields.
//
// A type is described by the value its constructor builds and its fields, in
// the order "new" takes them as arguments. Every field can also be read and
// written by name, alongside "option" which gives the option code.
var luaEDNS0Kinds = []luaEDNS0Kind{
	luaEDNS0Type("EDNS0_COOKIE",
		func() *dns.EDNS0_COOKIE { return &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE} },
		stringField("cookie", func(e *dns.EDNS0_COOKIE) *string { return &e.Cookie }),
	),
	luaEDNS0Type("EDNS0_DAU",
		func() *dns.EDNS0_DAU { return &dns.EDNS0_DAU{Code: dns.EDNS0DAU} },
		numberSliceField("algcode", func(e *dns.EDNS0_DAU) *[]uint8 { return &e.AlgCode }),
	),
	luaEDNS0Type("EDNS0_DHU",
		func() *dns.EDNS0_DHU { return &dns.EDNS0_DHU{Code: dns.EDNS0DHU} },
		numberSliceField("algcode", func(e *dns.EDNS0_DHU) *[]uint8 { return &e.AlgCode }),
	),
	luaEDNS0Type("EDNS0_EDE",
		func() *dns.EDNS0_EDE { return new(dns.EDNS0_EDE) },
		numberField("infocode", func(e *dns.EDNS0_EDE) *uint16 { return &e.InfoCode }),
		stringField("extratext", func(e *dns.EDNS0_EDE) *string { return &e.ExtraText }),
	),
	luaEDNS0Type("EDNS0_ESU",
		func() *dns.EDNS0_ESU { return &dns.EDNS0_ESU{Code: dns.EDNS0ESU} },
		stringField("uri", func(e *dns.EDNS0_ESU) *string { return &e.Uri }),
	),
	luaEDNS0Type("EDNS0_EXPIRE",
		func() *dns.EDNS0_EXPIRE { return &dns.EDNS0_EXPIRE{Code: dns.EDNS0EXPIRE} },
		numberField("expire", func(e *dns.EDNS0_EXPIRE) *uint32 { return &e.Expire }),
	),
	luaEDNS0Type("EDNS0_LLQ",
		func() *dns.EDNS0_LLQ { return &dns.EDNS0_LLQ{Code: dns.EDNS0LLQ} },
		numberField("version", func(e *dns.EDNS0_LLQ) *uint16 { return &e.Version }),
		numberField("opcode", func(e *dns.EDNS0_LLQ) *uint16 { return &e.Opcode }),
		numberField("error", func(e *dns.EDNS0_LLQ) *uint16 { return &e.Error }),
		numberField("id", func(e *dns.EDNS0_LLQ) *uint64 { return &e.Id }),
		numberField("leaselife", func(e *dns.EDNS0_LLQ) *uint32 { return &e.LeaseLife }),
	),
	luaEDNS0Type("EDNS0_LOCAL",
		func() *dns.EDNS0_LOCAL { return new(dns.EDNS0_LOCAL) },
		numberField("code", func(e *dns.EDNS0_LOCAL) *uint16 { return &e.Code }),
		bytesField("data", func(e *dns.EDNS0_LOCAL) *[]byte { return &e.Data }),
	),
	luaEDNS0Type("EDNS0_N3U",
		func() *dns.EDNS0_N3U { return &dns.EDNS0_N3U{Code: dns.EDNS0N3U} },
		numberSliceField("algcode", func(e *dns.EDNS0_N3U) *[]uint8 { return &e.AlgCode }),
	),
	luaEDNS0Type("EDNS0_NSID",
		func() *dns.EDNS0_NSID { return &dns.EDNS0_NSID{Code: dns.EDNS0NSID} },
		stringField("nsid", func(e *dns.EDNS0_NSID) *string { return &e.Nsid }),
	),
	luaEDNS0Type("EDNS0_PADDING",
		func() *dns.EDNS0_PADDING { return new(dns.EDNS0_PADDING) },
		bytesField("padding", func(e *dns.EDNS0_PADDING) *[]byte { return &e.Padding }),
	),
	luaEDNS0Type("EDNS0_SUBNET",
		func() *dns.EDNS0_SUBNET { return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET} },
		numberField("family", func(e *dns.EDNS0_SUBNET) *uint16 { return &e.Family }),
		numberField("sourcenetmask", func(e *dns.EDNS0_SUBNET) *uint8 { return &e.SourceNetmask }),
		numberField("sourcescope", func(e *dns.EDNS0_SUBNET) *uint8 { return &e.SourceScope }),
		ipField("address", func(e *dns.EDNS0_SUBNET) *net.IP { return &e.Address }),
	),
	luaEDNS0Type("EDNS0_TCP_KEEPALIVE",
		func() *dns.EDNS0_TCP_KEEPALIVE {
			return &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE}
		},
		numberField("timeout", func(e *dns.EDNS0_TCP_KEEPALIVE) *uint16 { return &e.Timeout }),
	),
	luaEDNS0Type("EDNS0_UL",
		func() *dns.EDNS0_UL { return &dns.EDNS0_UL{Code: dns.EDNS0UL} },
		numberField("lease", func(e *dns.EDNS0_UL) *uint32 { return &e.Lease }),
		numberField("keylease", func(e *dns.EDNS0_UL) *uint32 { return &e.KeyLease }),
	),
}

// luaEDNS0Kind is one EDNS0 option type: how it is registered, and how a value
// of it is handed to and read back from scripts.
type luaEDNS0Kind struct {
	typ   reflect.Type
	opts  []lua.Option
	value func(dns.EDNS0) lua.Value
	arg   func(lua.Value) (dns.EDNS0, bool)
}

var luaEDNS0ByType = func() map[reflect.Type]luaEDNS0Kind {
	m := make(map[reflect.Type]luaEDNS0Kind, len(luaEDNS0Kinds))
	for _, k := range luaEDNS0Kinds {
		m[k.typ] = k
	}
	return m
}()

func luaEDNS0Types() []lua.Option {
	opts := []lua.Option{
		// An option of a type scripts have no fields for still passes
		// through, with its code readable
		lua.Type[luaEDNS0](
			lua.Meta("__index", func(c *lua.Call) error {
				e := c.Arg[*luaEDNS0](0)
				if fieldName := c.Arg[string](1); fieldName != "option" {
					return c.ArgError(1, fmt.Sprintf("EDNS0 option does not have field %q", fieldName))
				}
				return c.Return(e.e.Option())
			}),
		),
	}
	for _, k := range luaEDNS0Kinds {
		opts = append(opts, k.opts...)
	}
	return opts
}

// luaEDNS0 holds an EDNS0 option of a type that scripts have no fields for.
type luaEDNS0 struct{ e dns.EDNS0 }

func luaEDNS0Value(e dns.EDNS0) lua.Value {
	if k, ok := luaEDNS0ByType[reflect.TypeOf(e)]; ok {
		return k.value(e)
	}
	return lua.ValueOf(&luaEDNS0{e})
}

// luaEDNS0Array reads an array of EDNS0 options a script assigns.
func luaEDNS0Array(v lua.Value) ([]dns.EDNS0, error) {
	values, err := luaArray[lua.Value](v)
	if err != nil {
		return nil, err
	}
	options := make([]dns.EDNS0, 0, len(values))
	for _, v := range values {
		e, ok := luaEDNS0Arg(v)
		if !ok {
			return nil, fmt.Errorf("expected EDNS0, got %v", v.Kind())
		}
		options = append(options, e)
	}
	return options, nil
}

func luaEDNS0Arg(v lua.Value) (dns.EDNS0, bool) {
	if e, err := v.As[*luaEDNS0](); err == nil && e != nil {
		return e.e, true
	}
	for _, k := range luaEDNS0Kinds {
		if e, ok := k.arg(v); ok {
			return e, true
		}
	}
	return nil, false
}

// edns0Field is one named field of an EDNS0 option type as scripts see it.
type edns0Field[T dns.EDNS0] struct {
	name string
	get  func(e T) lua.Value
	set  func(e T, v lua.Value) error
}

// Describes the Lua type for one EDNS0 option: a "new" constructor taking the
// fields as positional arguments, all of them optional, and metamethods to
// read and write them by name.
func luaEDNS0Type[E any, T interface {
	*E
	dns.EDNS0
}](name string, newOption func() T, fields ...edns0Field[T]) luaEDNS0Kind {
	byName := make(map[string]edns0Field[T], len(fields))
	for _, field := range fields {
		byName[field.name] = field
	}
	// Reports the field being read or written, or an error if the type
	// doesn't have it
	lookup := func(c *lua.Call) (edns0Field[T], error) {
		fieldName := c.Arg[string](1)
		field, ok := byName[fieldName]
		if !ok {
			return field, c.ArgError(1, fmt.Sprintf("%s does not have field %q", name, fieldName))
		}
		return field, nil
	}

	// All access goes through the metamethods, none to the Go fields
	var goFields []string
	for _, f := range reflect.VisibleFields(reflect.TypeFor[E]()) {
		if f.IsExported() {
			goFields = append(goFields, f.Name)
		}
	}

	opts := []lua.Option{
		lua.Type[E](
			lua.Hide(goFields...),
			// methods
			lua.Meta("__index", func(c *lua.Call) error {
				e := c.Arg[T](0)
				if c.Arg[string](1) == "option" {
					return c.Return(e.Option())
				}
				field, err := lookup(c)
				if err != nil {
					return err
				}
				return c.ReturnValues(field.get(e))
			}),
			lua.Meta("__newindex", func(c *lua.Call) error {
				e := c.Arg[T](0)
				field, err := lookup(c)
				if err != nil {
					return err
				}
				if err := field.set(e, c.Value(2)); err != nil {
					return c.ArgError(2, err.Error())
				}
				return nil
			}),
		),
		// static attributes
		lua.Module(name, lua.Members{
			"new": lua.GoFunc(func(c *lua.Call) error {
				e := newOption()
				for i, field := range fields {
					if c.Len() < i+1 {
						break
					}
					if err := field.set(e, c.Value(i)); err != nil {
						return c.ArgError(i, err.Error())
					}
				}
				return c.Return(e)
			}),
		}),
	}
	return luaEDNS0Kind{
		typ:   reflect.TypeFor[T](),
		opts:  opts,
		value: func(e dns.EDNS0) lua.Value { return lua.ValueOf(e.(T)) },
		arg: func(v lua.Value) (dns.EDNS0, bool) {
			e, err := v.As[T]()
			return e, err == nil && e != nil
		},
	}
}

// A numeric field, converted between Lua numbers and the field's own width.
func numberField[T dns.EDNS0, V numbers](name string, field func(T) *V) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(e T) lua.Value { return lua.Int(int64(*field(e))) },
		set: func(e T, v lua.Value) error {
			n, ok := v.Int()
			if !ok {
				return fmt.Errorf("expected number, got %v", v.Kind())
			}
			*field(e) = V(n)
			return nil
		},
	}
}

// A field of numbers, exposed as a Lua table.
func numberSliceField[T dns.EDNS0, V numbers](name string, field func(T) *[]V) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(e T) lua.Value { return lua.ValueOf(numberSliceToTable(*field(e))) },
		set: func(e T, v lua.Value) error {
			values, err := luaArray[V](v)
			if err != nil {
				return err
			}
			*field(e) = values
			return nil
		},
	}
}

func stringField[T dns.EDNS0](name string, field func(T) *string) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(e T) lua.Value { return lua.String(*field(e)) },
		set: func(e T, v lua.Value) error {
			s, ok := v.Str()
			if !ok {
				return fmt.Errorf("expected string, got %v", v.Kind())
			}
			*field(e) = s
			return nil
		},
	}
}

// A byte-slice field, exposed to scripts as a string.
func bytesField[T dns.EDNS0](name string, field func(T) *[]byte) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(e T) lua.Value { return lua.String(string(*field(e))) },
		set: func(e T, v lua.Value) error {
			s, ok := v.Str()
			if !ok {
				return fmt.Errorf("expected string, got %v", v.Kind())
			}
			*field(e) = []byte(s)
			return nil
		},
	}
}

// An IP address field, exposed as a string and rejected if it doesn't parse.
func ipField[T dns.EDNS0](name string, field func(T) *net.IP) edns0Field[T] {
	return edns0Field[T]{
		name: name,
		get:  func(e T) lua.Value { return lua.String(field(e).String()) },
		set: func(e T, v lua.Value) error {
			s, _ := v.Str()
			ip := net.ParseIP(s)
			if ip == nil {
				return fmt.Errorf("expected IP address, got %q", s)
			}
			*field(e) = ip
			return nil
		},
	}
}
