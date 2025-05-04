package rdns

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/miekg/dns"
	lua "github.com/yuin/gopher-lua"
)

// RR functions

const luaRRHeaderMetatableName = "RR"

func (s *LuaScript) RegisterRRTypes() {
	L := s.L

	mt := L.NewTypeMetatable(luaRRHeaderMetatableName)
	L.SetGlobal(luaRRHeaderMetatableName, mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(
		func(L *lua.LState) int {
			table := L.CheckTable(1)
			lrtype, ok := table.RawGetString("rtype").(lua.LNumber)
			if !ok {
				L.ArgError(1, "rtype must be a number")
				return 0
			}
			rtype := uint16(lrtype)

			rrFunc, ok := dns.TypeToRR[rtype]
			if !ok {
				L.ArgError(1, "unknown rtype")
				return 0
			}
			rr := rrFunc()

			var err error
			table.ForEach(func(k, v lua.LValue) {
				if k.Type() != lua.LTString {
					if err != nil { // Only record the first error
						err = fmt.Errorf("expecte string keys, got %s", k.Type().String())
					}
					return
				}
				if k.String() == "rtype" {
					// We don't allow this to be set or updated
					rr.Header().Rrtype = rtype
					return
				}
				if setErr := rrDB.set(rr, k.String(), v); setErr != nil && err == nil {
					err = setErr
				}
			})
			if err != nil {
				L.ArgError(1, err.Error())
				return 0
			}

			L.Push(userDataWithMetatable(L, luaRRHeaderMetatableName, rr))
			return 1
		}))

	// methods
	L.SetField(mt, "__index", L.NewFunction(
		func(L *lua.LState) int {
			rr, ok := getUserDataArg[dns.RR](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)

			lv, err := rrDB.get(rr, fieldName)
			if err != nil {
				L.ArgError(1, err.Error()) // TODO: figure out arg position
				return 0
			}
			L.Push(lv)
			return 1
		}))
	L.SetField(mt, "__newindex", L.NewFunction(
		func(L *lua.LState) int {
			rr, ok := getUserDataArg[dns.RR](L, 1)
			if !ok {
				return 0
			}
			fieldName := L.CheckString(2)
			if fieldName == "" {
				return 0
			}
			value := L.CheckAny(3)

			// TODO: handle header fields directly

			if err := rrDB.set(rr, fieldName, value); err != nil {
				L.ArgError(1, err.Error()) // TODO: figure out arg position
				return 0
			}
			return 0
		}))
}

type rrFieldDB map[reflect.Type]map[string]rrFieldAccessors

type rrFieldAccessors struct {
	index []int
	get   func(reflect.Value) (lua.LValue, error)
	set   func(reflect.Value, lua.LValue) error
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
			index: append(index, field.Index...),
		}
		switch field.Type {
		case reflect.TypeOf(net.IP{}):
			a.get, a.set = getIPField, setIPField
		case reflect.TypeOf(""):
			a.get, a.set = getStringField, setStringField
		case reflect.TypeOf(uint8(0)):
			a.get, a.set = getUint8Field, setUint8Field
		case reflect.TypeOf(uint16(0)):
			a.get, a.set = getUint16Field, setUint16Field
		case reflect.TypeOf(uint32(0)):
			a.get, a.set = getUint32Field, setUint32Field
		case reflect.TypeOf(uint64(0)):
			a.get, a.set = getUint64Field, setUint64Field
		case reflect.TypeOf([]uint16{}):
			a.get, a.set = getUint16SliceField, setUint16SliceField
		case reflect.TypeOf([]string{}):
			a.get, a.set = getStringSliceField, setStringSliceField
		case reflect.TypeOf(dns.DS{}): // Composed in DLV
			return rrFieldsForType(reflect.TypeOf(dns.DS{}), field.Index)
		case reflect.TypeOf(dns.SVCB{}): // Composed in HTTPS
			return rrFieldsForType(reflect.TypeOf(dns.SVCB{}), field.Index)
		case reflect.TypeOf(dns.NSEC{}): // Composed in NXT
			return rrFieldsForType(reflect.TypeOf(dns.NSEC{}), field.Index)
		case reflect.TypeOf([]dns.APLPrefix{}): // Used in APL
			a.get, a.set = getUnsupported(field.Name), setUnsupported(field.Name)
		case reflect.TypeOf(dns.RRSIG{}): // Composed in SIG
			return rrFieldsForType(reflect.TypeOf(dns.RRSIG{}), field.Index)
		case reflect.TypeOf(dns.DNSKEY{}): // Composed in KEY
			return rrFieldsForType(reflect.TypeOf(dns.DNSKEY{}), field.Index)
		case reflect.TypeOf([]dns.SVCBKeyValue{}): // interface
			a.get, a.set = getUnsupported(field.Name), setUnsupported(field.Name)
		case reflect.TypeOf([]dns.EDNS0{}): // in OPT
		// TODO:implement
		default:
			panic(fmt.Errorf("unsupported RR field value type %v in %s", field.Type, typ))
		}

		fields[strings.ToLower(field.Name)] = a
	}
	return fields
}

func (db rrFieldDB) get(rr dns.RR, name string) (lua.LValue, error) {
	// If the field is in the header, we handle that directly
	switch name {
	case "name":
		return lua.LString(rr.Header().Name), nil
	case "rtype":
		return lua.LNumber(rr.Header().Rrtype), nil
	case "class":
		return lua.LNumber(rr.Header().Class), nil
	case "ttl":
		return lua.LNumber(rr.Header().Ttl), nil
	case "rdlength":
		return lua.LNumber(rr.Header().Rdlength), nil
	}

	// Lookup the fields for this type
	typeFields, ok := db[reflect.TypeOf(rr)]
	if !ok {
		return nil, luaArgError{1, fmt.Errorf("unsupported resource record type %v", reflect.TypeOf(rr).String())}
	}
	a, ok := typeFields[name]
	if !ok {
		return nil, luaArgError{2, fmt.Errorf("unknown field name %q for type %v", name, reflect.TypeOf(rr).String())}
	}
	fieldValue := reflect.ValueOf(rr).Elem().FieldByIndex(a.index)
	return a.get(fieldValue)
}

func (db rrFieldDB) set(rr dns.RR, name string, value lua.LValue) error {
	// If the field is in the header, we handle that directly
	switch name {
	case "name":
		if value.Type() != lua.LTString {
			return luaArgError{3, fmt.Errorf("expected string value, got %v", value.Type().String())}
		}
		rr.Header().Name = value.String()
		return nil
	case "rtype":
		return luaArgError{2, fmt.Errorf("cannot change rtype directly")}
	case "class":
		if value.Type() != lua.LTNumber {
			return luaArgError{3, fmt.Errorf("expected number value, got %v", value.Type().String())}
		}
		rr.Header().Class = uint16(value.(lua.LNumber))
		return nil
	case "ttl":
		if value.Type() != lua.LTNumber {
			return luaArgError{3, fmt.Errorf("expected number value, got %v", value.Type().String())}
		}
		rr.Header().Ttl = uint32(value.(lua.LNumber))
		return nil
	case "rdlength":
		return luaArgError{2, fmt.Errorf("cannot change rdlength")}
	}

	// Lookup the fields for this type
	typeFields, ok := db[reflect.TypeOf(rr)]
	if !ok {
		return luaArgError{1, fmt.Errorf("unsupported resource record type %v", reflect.TypeOf(rr).String())}
	}
	a, ok := typeFields[name]
	if !ok {
		return luaArgError{2, fmt.Errorf("unknown field name %q for type %v", name, reflect.TypeOf(rr).String())}
	}
	fieldValue := reflect.ValueOf(rr).Elem().FieldByIndex(a.index)
	return a.set(fieldValue, value)
}

type luaArgError struct {
	position int
	error
}

func getStringField(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().(string)
	return lua.LString(field), nil
}

func setStringField(fieldValue reflect.Value, value lua.LValue) error {
	if value.Type() != lua.LTString {
		return luaArgError{3, fmt.Errorf("expected string value, got %v", value.Type().String())}
	}
	fieldValue.SetString(value.String())
	return nil
}

func getStringSliceField(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().([]string)
	table := (*lua.LState)(nil).CreateTable(len(field), 0)
	for _, v := range field {
		table.Append(lua.LString(v))
	}
	return table, nil
}

func setStringSliceField(fieldValue reflect.Value, value lua.LValue) error {
	if value.Type() != lua.LTTable {
		return luaArgError{3, fmt.Errorf("expected array, got %v", value.Type().String())}
	}
	table := value.(*lua.LTable)
	n := table.Len()
	stringValues := make([]string, 0, n)
	for i := range n {
		element := table.RawGetInt(i + 1)
		if element.Type() != lua.LTString {
			return luaArgError{3, fmt.Errorf("expected string, got %v", element.Type().String())}
		}
		s := element.String()
		stringValues = append(stringValues, s)
	}
	newVal := reflect.ValueOf(stringValues)
	fieldValue.Set(newVal)
	return nil
}

func getUint16SliceField(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().([]uint16)
	table := (*lua.LState)(nil).CreateTable(len(field), 0)
	for _, v := range field {
		table.Append(lua.LNumber(v))
	}
	return table, nil
}

func setUint16SliceField(fieldValue reflect.Value, value lua.LValue) error {
	if value.Type() != lua.LTTable {
		return luaArgError{3, fmt.Errorf("expected array, got %v", value.Type().String())}
	}
	table := value.(*lua.LTable)
	n := table.Len()
	values := make([]uint16, 0, n)
	for i := range n {
		element := table.RawGetInt(i + 1)
		if element.Type() != lua.LTNumber {
			return luaArgError{3, fmt.Errorf("expected number, got %v", element.Type().String())}
		}
		lv := element.(lua.LNumber)
		values = append(values, uint16(lv))
	}
	newVal := reflect.ValueOf(values)
	fieldValue.Set(newVal)
	return nil
}

func getUint8Field(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().(uint8)
	return lua.LNumber(field), nil
}

func setUint8Field(fieldValue reflect.Value, value lua.LValue) error {
	if value.Type() != lua.LTNumber {
		return luaArgError{3, fmt.Errorf("expected number, got %v", value.Type().String())}
	}
	fieldValue.SetUint(uint64(value.(lua.LNumber)))
	return nil
}

func getUint16Field(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().(uint16)
	return lua.LNumber(field), nil
}

func setUint16Field(fieldValue reflect.Value, value lua.LValue) error {
	if value.Type() != lua.LTNumber {
		return luaArgError{3, fmt.Errorf("expected number, got %v", value.Type().String())}
	}
	fieldValue.SetUint(uint64(value.(lua.LNumber)))
	return nil
}

func getUint32Field(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().(uint32)
	return lua.LNumber(field), nil
}

func setUint32Field(fieldValue reflect.Value, value lua.LValue) error {
	if value.Type() != lua.LTNumber {
		return luaArgError{3, fmt.Errorf("expected number, got %v", value.Type().String())}
	}
	fieldValue.SetUint(uint64(value.(lua.LNumber)))
	return nil
}

func getUint64Field(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().(uint64)
	return lua.LNumber(field), nil
}

func setUint64Field(fieldValue reflect.Value, value lua.LValue) error {
	if value.Type() != lua.LTNumber {
		return luaArgError{3, fmt.Errorf("expected number, got %v", value.Type().String())}
	}
	fieldValue.SetUint(uint64(value.(lua.LNumber)))
	return nil
}

func getIPField(fieldValue reflect.Value) (lua.LValue, error) {
	field := fieldValue.Interface().(net.IP)
	if field == nil {
		return lua.LNil, nil
	}
	return lua.LString(field.String()), nil
}

func setIPField(fieldValue reflect.Value, value lua.LValue) error {
	switch value.Type() {
	case lua.LTString:
		ip := net.ParseIP(value.String())
		if ip == nil {
			return nil
		}
		fieldValue.SetBytes(ip)
	case lua.LTNil:
		fieldValue.SetZero()
	default:
		return luaArgError{3, fmt.Errorf("expected string or nil, got %v", value.Type().String())}
	}
	return nil
}

func getUnsupported(name string) func(v reflect.Value) (lua.LValue, error) {
	return func(v reflect.Value) (lua.LValue, error) {
		return nil, luaArgError{2, fmt.Errorf("getting %q not supported", name)}
	}
}

func setUnsupported(name string) func(v reflect.Value, value lua.LValue) error {
	return func(v reflect.Value, value lua.LValue) error {
		return luaArgError{2, fmt.Errorf("setting %q not supported", name)}
	}
}
