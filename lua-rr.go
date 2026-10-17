//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"

	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

// RR functions

// luaRR is a resource record as scripts see it. Records come in many types,
// which share one set of accessors in __index and __newindex.
type luaRR struct{ rr dns.RR }

func luaRRValue(rr dns.RR) lua.Value {
	return lua.ValueOf(&luaRR{rr})
}

// luaRRArg returns the record a value holds. An OPT record, which scripts get
// from Message:is_edns0() or OPT.new(), is a record too.
func luaRRArg(v lua.Value) (dns.RR, error) {
	if rr, err := v.As[*luaRR](); err == nil && rr != nil {
		return rr.rr, nil
	}
	if opt, err := v.As[*dns.OPT](); err == nil && opt != nil {
		return opt, nil
	}
	return nil, fmt.Errorf("invalid type, expected RR, got %v", v.Kind())
}

func luaRRType() []lua.Option {
	return []lua.Option{
		lua.Type[luaRR](
			// methods
			lua.Meta("__index", func(c *lua.Call) error {
				rr := c.Arg[*luaRR](0)
				v, err := rrDB.get(rr.rr, c.Arg[string](1))
				if err != nil {
					return c.ArgError(1, err.Error())
				}
				return c.ReturnValues(v)
			}),
			lua.Meta("__newindex", func(c *lua.Call) error {
				rr := c.Arg[*luaRR](0)
				if err := rrDB.set(rr.rr, c.Arg[string](1), c.Value(2)); err != nil {
					return c.ArgError(1, err.Error())
				}
				return nil
			}),
		),
		// static attributes
		lua.Module("RR", lua.Members{
			"new": lua.GoFunc(func(c *lua.Call) error {
				table := c.Arg[*lua.Table](0)
				lrtype, ok := table.Get(lua.String("rtype")).Int()
				if !ok {
					return c.ArgError(0, "rtype must be a number")
				}
				rtype := uint16(lrtype)

				rrFunc, ok := dns.TypeToRR[rtype]
				if !ok {
					return c.ArgError(0, "unknown rtype")
				}
				rr := rrFunc()

				for k, v := range table.All() {
					name, ok := k.Str()
					if !ok {
						return c.ArgError(0, fmt.Sprintf("expected string keys, got %v", k.Kind()))
					}
					if name == "rtype" {
						// We don't allow this to be set or updated
						rr.Header().Rrtype = rtype
						continue
					}
					if err := rrDB.set(rr, name, v); err != nil {
						return c.ArgError(0, err.Error())
					}
				}
				return c.ReturnValues(luaRRValue(rr))
			}),
		}),
	}
}

type rrFieldDB map[reflect.Type]map[string]rrFieldAccessors

type rrFieldAccessors struct {
	index []int
	get   func(reflect.Value) (lua.Value, error)
	set   func(reflect.Value, lua.Value) error
}

var rrDB = func() rrFieldDB {
	db := make(map[reflect.Type]map[string]rrFieldAccessors)

	for _, rrFunc := range dns.TypeToRR {
		rr := rrFunc()
		typ := reflect.TypeOf(rr)
		db[typ] = rrFieldsForType(typ.Elem(), nil)
	}
	return db
}()

func rrFieldsForType(typ reflect.Type, index []int) map[string]rrFieldAccessors {
	fields := make(map[string]rrFieldAccessors)
	for _, field := range reflect.VisibleFields(typ) {
		if !field.IsExported() {
			continue
		}
		// All RR have a header and we handle that directly, without reflection
		if field.Name == "Hdr" {
			continue
		}
		a := rrFieldAccessors{
			index: append(slices.Clone(index), field.Index...),
		}
		switch field.Type {
		case reflect.TypeFor[net.IP]():
			a.get, a.set = getIPField, setIPField
		case reflect.TypeFor[string]():
			a.get, a.set = getStringField, setStringField
		case reflect.TypeFor[uint8](), reflect.TypeFor[uint16](), reflect.TypeFor[uint32](), reflect.TypeFor[uint64]():
			a.get, a.set = getUintField, setUintField
		case reflect.TypeFor[[]uint16]():
			a.get, a.set = getUint16SliceField, setUint16SliceField
		case reflect.TypeFor[[]string]():
			a.get, a.set = getStringSliceField, setStringSliceField
		case reflect.TypeFor[dns.DS](): // Composed in DLV
			return rrFieldsForType(reflect.TypeFor[dns.DS](), field.Index)
		case reflect.TypeFor[dns.SVCB](): // Composed in HTTPS
			return rrFieldsForType(reflect.TypeFor[dns.SVCB](), field.Index)
		case reflect.TypeFor[dns.NSEC](): // Composed in NXT
			return rrFieldsForType(reflect.TypeFor[dns.NSEC](), field.Index)
		case reflect.TypeFor[[]dns.APLPrefix](): // Used in APL
			a.get, a.set = getUnsupported(field.Name), setUnsupported(field.Name)
		case reflect.TypeFor[dns.RRSIG](): // Composed in SIG
			return rrFieldsForType(reflect.TypeFor[dns.RRSIG](), field.Index)
		case reflect.TypeFor[dns.DNSKEY](): // Composed in KEY
			return rrFieldsForType(reflect.TypeFor[dns.DNSKEY](), field.Index)
		case reflect.TypeFor[[]dns.SVCBKeyValue](): // interface
			a.get, a.set = getUnsupported(field.Name), setUnsupported(field.Name)
		case reflect.TypeFor[[]dns.EDNS0](): // in OPT
			a.get, a.set = getEDNS0SliceField, setEDNS0SliceField
		default:
			panic(fmt.Errorf("unsupported RR field value type %v in %s", field.Type, typ))
		}

		fields[strings.ToLower(field.Name)] = a
	}
	return fields
}

func (db rrFieldDB) get(rr dns.RR, name string) (lua.Value, error) {
	// If the field is in the header, we handle that directly
	switch name {
	case "name":
		return lua.String(rr.Header().Name), nil
	case "rtype":
		return lua.Int(int64(rr.Header().Rrtype)), nil
	case "class":
		return lua.Int(int64(rr.Header().Class)), nil
	case "ttl":
		return lua.Int(int64(rr.Header().Ttl)), nil
	case "rdlength":
		return lua.Int(int64(rr.Header().Rdlength)), nil
	}

	a, err := db.lookup(rr, name)
	if err != nil {
		return lua.Value{}, err
	}
	fieldValue := reflect.ValueOf(rr).Elem().FieldByIndex(a.index)
	return a.get(fieldValue)
}

func (db rrFieldDB) set(rr dns.RR, name string, value lua.Value) error {
	// If the field is in the header, we handle that directly
	switch name {
	case "name":
		s, ok := value.Str()
		if !ok {
			return fmt.Errorf("expected string value, got %v", value.Kind())
		}
		rr.Header().Name = s
		return nil
	case "rtype":
		return fmt.Errorf("cannot change rtype directly")
	case "class":
		n, err := luaUint(value)
		if err != nil {
			return err
		}
		rr.Header().Class = uint16(n)
		return nil
	case "ttl":
		n, err := luaUint(value)
		if err != nil {
			return err
		}
		rr.Header().Ttl = uint32(n)
		return nil
	case "rdlength":
		return fmt.Errorf("cannot change rdlength")
	}

	a, err := db.lookup(rr, name)
	if err != nil {
		return err
	}
	fieldValue := reflect.ValueOf(rr).Elem().FieldByIndex(a.index)
	return a.set(fieldValue, value)
}

// lookup finds the accessors of a field in the record's type
func (db rrFieldDB) lookup(rr dns.RR, name string) (rrFieldAccessors, error) {
	typeFields, ok := db[reflect.TypeOf(rr)]
	if !ok {
		return rrFieldAccessors{}, fmt.Errorf("unsupported resource record type %v", reflect.TypeOf(rr).String())
	}
	a, ok := typeFields[name]
	if !ok {
		return rrFieldAccessors{}, fmt.Errorf("unknown field name %q for type %v", name, reflect.TypeOf(rr).String())
	}
	return a, nil
}

// luaUint reads a number a script assigns to an unsigned field.
func luaUint(value lua.Value) (uint64, error) {
	n, ok := value.Int()
	if !ok {
		return 0, fmt.Errorf("expected number, got %v", value.Kind())
	}
	return uint64(n), nil
}

func getStringField(fieldValue reflect.Value) (lua.Value, error) {
	return lua.String(fieldValue.String()), nil
}

func setStringField(fieldValue reflect.Value, value lua.Value) error {
	s, ok := value.Str()
	if !ok {
		return fmt.Errorf("expected string value, got %v", value.Kind())
	}
	fieldValue.SetString(s)
	return nil
}

func getStringSliceField(fieldValue reflect.Value) (lua.Value, error) {
	field := fieldValue.Interface().([]string)
	return lua.ValueOf(luaTable(field, lua.String)), nil
}

func setStringSliceField(fieldValue reflect.Value, value lua.Value) error {
	values, err := luaArray[string](value)
	if err != nil {
		return err
	}
	fieldValue.Set(reflect.ValueOf(values))
	return nil
}

func getUint16SliceField(fieldValue reflect.Value) (lua.Value, error) {
	return lua.ValueOf(numberSliceToTable(fieldValue.Interface().([]uint16))), nil
}

func setUint16SliceField(fieldValue reflect.Value, value lua.Value) error {
	values, err := luaArray[uint16](value)
	if err != nil {
		return err
	}
	fieldValue.Set(reflect.ValueOf(values))
	return nil
}

// Gets an unsigned integer field of any width
func getUintField(fieldValue reflect.Value) (lua.Value, error) {
	return lua.Int(int64(fieldValue.Uint())), nil
}

// Sets an unsigned integer field of any width
func setUintField(fieldValue reflect.Value, value lua.Value) error {
	n, err := luaUint(value)
	if err != nil {
		return err
	}
	fieldValue.SetUint(n)
	return nil
}

func getIPField(fieldValue reflect.Value) (lua.Value, error) {
	field := fieldValue.Interface().(net.IP)
	if field == nil {
		return lua.Value{}, nil
	}
	return lua.String(field.String()), nil
}

func setIPField(fieldValue reflect.Value, value lua.Value) error {
	switch value.Kind() {
	case lua.KindString:
		s, _ := value.Str()
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("invalid IP address %q", s)
		}
		fieldValue.SetBytes(ip)
	case lua.KindNil:
		fieldValue.SetZero()
	default:
		return fmt.Errorf("expected string or nil, got %v", value.Kind())
	}
	return nil
}

func getEDNS0SliceField(fieldValue reflect.Value) (lua.Value, error) {
	field := fieldValue.Interface().([]dns.EDNS0)
	return lua.ValueOf(luaTable(field, luaEDNS0Value)), nil
}

func setEDNS0SliceField(fieldValue reflect.Value, value lua.Value) error {
	options, err := luaEDNS0Array(value)
	if err != nil {
		return err
	}
	fieldValue.Set(reflect.ValueOf(options))
	return nil
}

func getUnsupported(name string) func(v reflect.Value) (lua.Value, error) {
	return func(v reflect.Value) (lua.Value, error) {
		return lua.Value{}, fmt.Errorf("getting %q not supported", name)
	}
}

func setUnsupported(name string) func(v reflect.Value, value lua.Value) error {
	return func(v reflect.Value, value lua.Value) error {
		return fmt.Errorf("setting %q not supported", name)
	}
}
