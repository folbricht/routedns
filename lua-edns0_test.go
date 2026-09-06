package rdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Every registered EDNS0 type, with the constructor call a script would write,
// the option code it must report, and the fields it exposes with a value to
// assign and read back.
var luaEDNS0Types = []struct {
	name   string
	new    string
	option uint16
	fields map[string]string // field name -> Lua expression, compared with ==
}{
	{
		name: "EDNS0_COOKIE", new: `EDNS0_COOKIE.new("24a5ac1a012345ff")`, option: dns.EDNS0COOKIE,
		fields: map[string]string{"cookie": `"aabb"`},
	},
	{
		name: "EDNS0_DAU", new: `EDNS0_DAU.new({ 1, 2, 3 })`, option: dns.EDNS0DAU,
	},
	{
		name: "EDNS0_DHU", new: `EDNS0_DHU.new({ 1, 2, 3 })`, option: dns.EDNS0DHU,
	},
	{
		name: "EDNS0_EDE", new: `EDNS0_EDE.new(15, "domain blocked")`, option: dns.EDNS0EDE,
		fields: map[string]string{"infocode": "16", "extratext": `"censored"`},
	},
	{
		name: "EDNS0_ESU", new: `EDNS0_ESU.new("http://example.com")`, option: dns.EDNS0ESU,
		fields: map[string]string{"uri": `"sip:example.com"`},
	},
	{
		name: "EDNS0_EXPIRE", new: `EDNS0_EXPIRE.new(123)`, option: dns.EDNS0EXPIRE,
		fields: map[string]string{"expire": "124"},
	},
	{
		name: "EDNS0_LLQ", new: `EDNS0_LLQ.new(1, 16, 0, 1234, 4321)`, option: dns.EDNS0LLQ,
		fields: map[string]string{"version": "2", "opcode": "17", "error": "3", "id": "99", "leaselife": "60"},
	},
	{
		// LOCAL is the one type whose option code is the code it was given.
		name: "EDNS0_LOCAL", new: `EDNS0_LOCAL.new(65001, "somedata")`, option: 65001,
		fields: map[string]string{"code": "65001", "data": `"other"`},
	},
	{
		name: "EDNS0_N3U", new: `EDNS0_N3U.new({ 1, 2, 3 })`, option: dns.EDNS0N3U,
	},
	{
		// NSID packs as hex, so the value has to be one.
		name: "EDNS0_NSID", new: `EDNS0_NSID.new("abcd")`, option: dns.EDNS0NSID,
		fields: map[string]string{"nsid": `"beef"`},
	},
	{
		name: "EDNS0_PADDING", new: `EDNS0_PADDING.new("somepadding")`, option: dns.EDNS0PADDING,
		fields: map[string]string{"padding": `"more"`},
	},
	{
		name: "EDNS0_SUBNET", new: `EDNS0_SUBNET.new(1, 32, 0, "192.168.0.0")`, option: dns.EDNS0SUBNET,
		fields: map[string]string{"family": "2", "sourcenetmask": "24", "sourcescope": "1", "address": `"10.0.0.1"`},
	},
	{
		name: "EDNS0_TCP_KEEPALIVE", new: `EDNS0_TCP_KEEPALIVE.new(1)`, option: dns.EDNS0TCPKEEPALIVE,
		fields: map[string]string{"timeout": "10"},
	},
	{
		name: "EDNS0_UL", new: `EDNS0_UL.new(1, 2)`, option: dns.EDNS0UL,
		fields: map[string]string{"lease": "10", "keylease": "20"},
	},
}

// The option code a script reads is the one the option carries on the wire.
func TestLuaEDNS0OptionCode(t *testing.T) {
	for _, tt := range luaEDNS0Types {
		t.Run(tt.name, func(t *testing.T) {
			runLuaEDNS0Check(t, fmt.Sprintf(`
	local e = %s
	if e.option ~= %d then
		return nil, Error.new("wrong option code: " .. e.option)
	end`, tt.new, tt.option))
		})
	}
}

// Each field assigned through the metatable reads back as it was written.
func TestLuaEDNS0FieldRoundTrip(t *testing.T) {
	for _, tt := range luaEDNS0Types {
		t.Run(tt.name, func(t *testing.T) {
			for field, value := range tt.fields {
				runLuaEDNS0Check(t, fmt.Sprintf(`
	local e = %s
	e.%s = %s
	if e.%s ~= %s then
		return nil, Error.new("%s did not round-trip")
	end`, tt.new, field, value, field, value, field))
			}
		})
	}
}

// Slice fields come back as a table of numbers, indexed from 1.
func TestLuaEDNS0SliceFieldRoundTrip(t *testing.T) {
	for _, name := range []string{"EDNS0_DAU", "EDNS0_DHU", "EDNS0_N3U"} {
		t.Run(name, func(t *testing.T) {
			runLuaEDNS0Check(t, fmt.Sprintf(`
	local e = %s.new({ 1, 2, 3 })
	if e.algcode[1] ~= 1 or e.algcode[3] ~= 3 then
		return nil, Error.new("constructor value not readable")
	end
	e.algcode = { 8, 9 }
	if e.algcode[1] ~= 8 or e.algcode[2] ~= 9 then
		return nil, Error.new("assigned value not readable")
	end`, name))
		})
	}
}

// Reading or writing a field the type doesn't have is an error naming both.
func TestLuaEDNS0UnknownField(t *testing.T) {
	for _, tt := range luaEDNS0Types {
		t.Run(tt.name, func(t *testing.T) {
			for _, script := range []string{
				fmt.Sprintf("local e = %s\n\tlocal v = e.nosuchfield", tt.new),
				fmt.Sprintf("local e = %s\n\te.nosuchfield = 1", tt.new),
			} {
				err := runLuaEDNS0Script(t, script)
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.name+` does not have field "nosuchfield"`)
			}
		})
	}
}

// An address that isn't an IP is rejected, in the constructor and on assignment.
func TestLuaEDNS0SubnetInvalidAddress(t *testing.T) {
	for _, script := range []string{
		`local e = EDNS0_SUBNET.new(1, 32, 0, "not-an-ip")`,
		`local e = EDNS0_SUBNET.new(1, 32, 0, "192.168.0.0")
	e.address = "not-an-ip"`,
	} {
		err := runLuaEDNS0Script(t, script)
		require.Error(t, err)
		require.Contains(t, err.Error(), `expected IP address, got "not-an-ip"`)
	}
}

// Options built in a script survive a round trip through the wire format,
// which is what the option code they carry is for.
func TestLuaEDNS0AttachedToQuery(t *testing.T) {
	for _, tt := range luaEDNS0Types {
		t.Run(tt.name, func(t *testing.T) {
			var got *dns.Msg
			resolver := &TestResolver{
				ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
					packed, err := q.Pack()
					require.NoError(t, err)
					got = new(dns.Msg)
					require.NoError(t, got.Unpack(packed))
					a := new(dns.Msg)
					a.SetReply(q)
					return a, nil
				},
			}
			r, err := NewLua("test-lua", LuaOptions{Script: fmt.Sprintf(`
function Resolve(msg, ci)
	local opt = OPT.new()
	opt.option = { %s }
	msg.extra = { opt }
	local resolver = Resolvers[1]
	return resolver:resolve(msg, ci)
end`, tt.new)}, resolver)
			require.NoError(t, err)

			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			_, err = r.Resolve(q, ClientInfo{})
			require.NoError(t, err)

			require.NotNil(t, got)
			edns0 := got.IsEdns0()
			require.NotNil(t, edns0)
			require.Len(t, edns0.Option, 1)
			require.Equal(t, tt.option, edns0.Option[0].Option())
		})
	}
}

// Runs a script fragment that returns an Error when it finds a bad value, and
// fails the test with it.
func runLuaEDNS0Check(t *testing.T, body string) {
	t.Helper()
	require.NoError(t, runLuaEDNS0Script(t, body))
}

// Runs a script fragment inside a Resolve function and returns whatever went
// wrong, whether raised by Lua or returned by the script.
func runLuaEDNS0Script(t *testing.T, body string) error {
	t.Helper()
	script := "function Resolve(msg, ci)\n\t" + strings.TrimLeft(body, "\n\t") + "\n\treturn nil, nil\nend"
	r, err := NewLua("test-lua", LuaOptions{Script: script}, new(TestResolver))
	require.NoError(t, err)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = r.Resolve(q, ClientInfo{})
	return err
}
