package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLuaSimplePassthrough(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	local resolver = Resolvers[1]
	local answer, err = resolver:resolve(msg, ci)
	if err ~= nil then
		return nil, err
	end
	return answer, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err = r.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, resolver.HitCount())
}

func TestLuaMissingResolveFunc(t *testing.T) {
	opt := LuaOptions{
		Script: `function test() return nil, nil end`,
	}

	resolver := new(TestResolver)

	_, err := NewLua("test-lua", opt, resolver)
	require.Error(t, err)
}

func TestLuaResolveError(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	return nil, Error.new("no bueno")
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err = r.Resolve(q, ci)
	require.Error(t, err)
	require.Zero(t, resolver.HitCount())
}

func TestLuaStaticAnswer(t *testing.T) {
	tests := map[string]LuaOptions{
		"set_questions": {
			Script: `
function Resolve(msg, ci)
	local question = Question.new("example.com.", TypeA)
	local answer = Message.new()
	answer.id = msg.id
	answer.questions = { question }
	answer.response = true
	answer.rcode = RcodeNXDOMAIN
	return answer, nil
end`,
		},
		"set_question": {
			Script: `
function Resolve(msg, ci)
	local answer = Message.new()
	answer:set_question("example.com.", TypeA)
	answer.id = msg.id
	answer.response = true
	answer.rcode = RcodeNXDOMAIN
	return answer, nil
end`,
		},
		"set_reply": {
			Script: `
function Resolve(msg, ci)
	local answer = Message.new()
	answer:set_reply(msg)
	answer.rcode = RcodeNXDOMAIN
	return answer, nil
end`,
		},
	}

	for name, opt := range tests {
		t.Run(name, func(t *testing.T) {
			var ci ClientInfo
			resolver := new(TestResolver)

			r, err := NewLua("test-lua", opt, resolver)
			require.NoError(t, err)

			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			q.Id = 1234

			answer, err := r.Resolve(q, ci)
			require.NoError(t, err)
			require.Equal(t, 0, resolver.HitCount())
			require.Equal(t, "example.com.", answer.Question[0].Name)
			require.Equal(t, dns.TypeA, answer.Question[0].Qtype)
			require.Equal(t, uint16(1234), answer.Id)
			require.Equal(t, dns.RcodeNameError, answer.Rcode)
			require.True(t, answer.Response)
		})
	}
}

func TestLuaQuestionOperations(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	-- Create a new Question record and test value set/get operations
	local question = Question.new("example.com.", TypeA)
	if question.name ~= "example.com." or question.qtype ~= TypeA then
		return nil, Error.new("unexpected name value")
	end
	question.name = "testing."
	if question.name ~= "testing." then
		return nil, Error.new("unexpected name value")
	end
	return nil, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeMX)

	_, err = r.Resolve(q, ci)
	require.NoError(t, err)
}

func TestLuaRROperations(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	-- Create a new TXT record and test value set/get operations
	rr = RR.new({rtype=TypeTXT, name="example.com.", class=ClassIN, ttl=60, txt={"hello", "world"}})
	if rr.txt[1] ~= "hello" then
		return nil, Error.new("unexpected value")
	end
	rr.txt = {"bla"}
	if rr.txt[1] ~= "bla" then
		return nil, Error.new("unexpected value in txt")
	end

	-- Create a new A record and test value set/get operations
	rr = RR.new({rtype=TypeA, name="example.com.", class=ClassIN, ttl=60, a="1.2.3.4"})
	if rr.rtype ~= TypeA or rr.name ~= "example.com." then
		return nil, Error.new("unexpected name value")
	end
	rr.a = "1.1.1.1"
	if rr.a ~= "1.1.1.1" then
		return nil, Error.new("unexpected ip value")
	end
	return nil, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeMX)

	_, err = r.Resolve(q, ci)
	require.NoError(t, err)
}

func TestLuaEDNS0Operations(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	-- Create a new EDNS0 COOKIE and test value set/get operations
	edns0 = EDNS0_COOKIE.new("24a5ac1a012345ff")
	if edns0.cookie ~= "24a5ac1a012345ff" then
		return nil, Error.new("unexpected value")
	end
	edns0.cookie = "bla"
	if edns0.cookie ~= "bla" then
		return nil, Error.new("unexpected value in edns0 cookie")
	end

	-- Create a new EDNS0 DAU and test value set/get operations
	edns0 = EDNS0_DAU.new({ 1, 2, 3 })
	if edns0.algcode[1] ~= 1 then
		return nil, Error.new("unexpected value")
	end
	edns0.algcode = { 0 }
	if edns0.algcode[1] ~= 0 then
		return nil, Error.new("unexpected value in edns0 dau")
	end
	
	-- Create a new EDNS0 DHU and test value set/get operations
	edns0 = EDNS0_DHU.new({ 1, 2, 3 })
	if edns0.algcode[1] ~= 1 then
		return nil, Error.new("unexpected value")
	end
	edns0.algcode = { 0 }
	if edns0.algcode[1] ~= 0 then
		return nil, Error.new("unexpected value in edns0 dhu")
	end

	-- Create a new EDNS0 EDE and test value set/get operations
	edns0 = EDNS0_EDE.new(15, "domain blocked")
	if edns0.infocode ~= 15 then
		return nil, Error.new("unexpected value")
	end
	edns0.extratext = "testing"
	if edns0.extratext ~= "testing" then
		return nil, Error.new("unexpected value in edns0 ede")
	end

	-- Create a new EDNS0 ESU and test value set/get operations
	edns0 = EDNS0_ESU.new("http://example.com")
	if edns0.uri ~= "http://example.com" then
		return nil, Error.new("unexpected value")
	end
	edns0.uri = "http://example.org"
	if edns0.uri ~= "http://example.org" then
		return nil, Error.new("unexpected value in edns0 ede")
	end

	-- Create a new EDNS0 EXPIRE and test value set/get operations
	edns0 = EDNS0_EXPIRE.new(123)
	if edns0.expire ~= 123 then
		return nil, Error.new("unexpected value")
	end
	edns0.expire = 124
	if edns0.expire ~= 124 then
		return nil, Error.new("unexpected value in edns0 expire")
	end

	-- Create a new EDNS0 LLQ and test value set/get operations
	edns0 = EDNS0_LLQ.new(1, 16, 0, 1234, 4321)
	if edns0.version ~= 1 then
		return nil, Error.new("unexpected value")
	end
	if edns0.opcode ~= 16 then
		return nil, Error.new("unexpected value")
	end
	if edns0.error ~= 0 then
		return nil, Error.new("unexpected value")
	end
	if edns0.id ~= 1234 then
		return nil, Error.new("unexpected value")
	end
	if edns0.leaselife ~= 4321 then
		return nil, Error.new("unexpected value")
	end
	edns0.error = 1
	if edns0.error ~= 1 then
		return nil, Error.new("unexpected value in edns0 llq")
	end

	-- Create a new EDNS0 LOCAL and test value set/get operations
	edns0 = EDNS0_LOCAL.new(65001, "somedata")
	if edns0.code ~= 65001 then
		return nil, Error.new("unexpected value")
	end
	edns0.data = "otherdata"
	if edns0.data ~= "otherdata" then
		return nil, Error.new("unexpected value in edns0 local")
	end

	-- Create a new EDNS0 N3U and test value set/get operations
	edns0 = EDNS0_N3U.new({ 1, 2, 3 })
	if edns0.algcode[1] ~= 1 then
		return nil, Error.new("unexpected value")
	end
	edns0.algcode = { 0 }
	if edns0.algcode[1] ~= 0 then
		return nil, Error.new("unexpected value in edns0 n3u")
	end
	
	-- Create a new EDNS0 NSID and test value set/get operations
	edns0 = EDNS0_NSID.new("someid")
	if edns0.nsid ~= "someid" then
		return nil, Error.new("unexpected value")
	end
	edns0.nsid = "otherid"
	if edns0.nsid ~= "otherid" then
		return nil, Error.new("unexpected value in edns0 nsid")
	end

	-- Create a new EDNS0 PADDING and test value set/get operations
	edns0 = EDNS0_PADDING.new("somepadding")
	if edns0.padding ~= "somepadding" then
		return nil, Error.new("unexpected value")
	end
	edns0.padding = "otherpadding"
	if edns0.padding ~= "otherpadding" then
		return nil, Error.new("unexpected value in edns0 padding")
	end

	-- Create a new EDNS0 SUBNET and test value set/get operations
	edns0 = EDNS0_SUBNET.new(1, 32, 0, "192.168.0.0")
	if edns0.family ~= 1 then
		return nil, Error.new("unexpected value")
	end
	if edns0.sourcenetmask ~= 32 then
		return nil, Error.new("unexpected value")
	end
	if edns0.sourcescope ~= 0 then
		return nil, Error.new("unexpected value")
	end
	if edns0.address ~= "192.168.0.0" then
		return nil, Error.new("unexpected value")
	end
	edns0.address = "172.16.0.0"
	if edns0.address ~= "172.16.0.0" then
		return nil, Error.new("unexpected value in edns0 subnet")
	end

	-- Create a new EDNS0 TCP_KEEPALIVE and test value set/get operations
	edns0 = EDNS0_TCP_KEEPALIVE.new(1)
	if edns0.timeout ~= 1 then
		return nil, Error.new("unexpected value")
	end
	edns0.timeout = 2
	if edns0.timeout ~= 2 then
		return nil, Error.new("unexpected value in edns0 tcp keepalive")
	end

	-- Create a new EDNS0 UL and test value set/get operations
	edns0 = EDNS0_UL.new(1, 2)
	if edns0.lease ~= 1 then
		return nil, Error.new("unexpected value")
	end
	edns0.keylease = 3
	if edns0.keylease ~= 3 then
		return nil, Error.new("unexpected value in edns0 ul")
	end

	return nil, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeMX)

	_, err = r.Resolve(q, ci)
	require.NoError(t, err)
}

func TestLuaMessageAnswerNsExtra(t *testing.T) {
	t.Run("construct_response", func(t *testing.T) {
		// Test that Lua scripts can set answer, ns, and extra sections
		opt := LuaOptions{
			Script: `
function Resolve(msg, ci)
	local answer = Message.new()
	answer:set_reply(msg)

	-- Add an A record to the answer section
	local a = RR.new({rtype=TypeA, name="example.com.", class=ClassIN, ttl=300, a="1.2.3.4"})
	answer.answer = { a }

	-- Add an NS record to the authority section
	local ns = RR.new({rtype=TypeNS, name="example.com.", class=ClassIN, ttl=3600, ns="ns1.example.com."})
	answer.ns = { ns }

	-- Add an A record to the additional section
	local extra = RR.new({rtype=TypeA, name="ns1.example.com.", class=ClassIN, ttl=300, a="5.6.7.8"})
	answer.extra = { extra }

	return answer, nil
end`,
		}

		var ci ClientInfo
		resolver := new(TestResolver)

		r, err := NewLua("test-lua", opt, resolver)
		require.NoError(t, err)

		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)

		a, err := r.Resolve(q, ci)
		require.NoError(t, err)

		// Verify answer section
		require.Len(t, a.Answer, 1)
		aRR, ok := a.Answer[0].(*dns.A)
		require.True(t, ok)
		require.Equal(t, "example.com.", aRR.Hdr.Name)
		require.Equal(t, net.ParseIP("1.2.3.4").To4(), aRR.A.To4())
		require.Equal(t, uint32(300), aRR.Hdr.Ttl)

		// Verify ns section
		require.Len(t, a.Ns, 1)
		nsRR, ok := a.Ns[0].(*dns.NS)
		require.True(t, ok)
		require.Equal(t, "example.com.", nsRR.Hdr.Name)
		require.Equal(t, "ns1.example.com.", nsRR.Ns)

		// Verify extra section
		require.Len(t, a.Extra, 1)
		extraRR, ok := a.Extra[0].(*dns.A)
		require.True(t, ok)
		require.Equal(t, "ns1.example.com.", extraRR.Hdr.Name)
		require.Equal(t, net.ParseIP("5.6.7.8").To4(), extraRR.A.To4())
	})

	t.Run("read_incoming", func(t *testing.T) {
		// Test that Lua scripts can read answer/ns/extra from an upstream response
		opt := LuaOptions{
			Script: `
function Resolve(msg, ci)
	-- Forward to upstream
	local resp, err = Resolvers[1]:resolve(msg, ci)
	if err ~= nil then
		return nil, err
	end

	-- Read the answer section and verify values
	local answers = resp.answer
	if #answers ~= 1 then
		return nil, Error.new("expected 1 answer, got " .. #answers)
	end
	if answers[1].a ~= "10.0.0.1" then
		return nil, Error.new("unexpected answer IP: " .. answers[1].a)
	end

	-- Read the ns section
	local ns = resp.ns
	if #ns ~= 1 then
		return nil, Error.new("expected 1 ns, got " .. #ns)
	end
	if ns[1].ns ~= "ns1.test." then
		return nil, Error.new("unexpected ns: " .. ns[1].ns)
	end

	-- Read the extra section
	local extra = resp.extra
	if #extra ~= 1 then
		return nil, Error.new("expected 1 extra, got " .. #extra)
	end
	if extra[1].a ~= "10.0.0.2" then
		return nil, Error.new("unexpected extra IP: " .. extra[1].a)
	end

	return resp, nil
end`,
		}

		var ci ClientInfo

		// Build a response with all sections populated
		response := new(dns.Msg)
		response.SetQuestion("test.example.", dns.TypeA)
		response.Response = true
		response.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "test.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("10.0.0.1"),
			},
		}
		response.Ns = []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: "test.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  "ns1.test.",
			},
		}
		response.Extra = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "ns1.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("10.0.0.2"),
			},
		}

		resolver := &TestResolver{
			ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
				return response, nil
			},
		}

		r, err := NewLua("test-lua", opt, resolver)
		require.NoError(t, err)

		q := new(dns.Msg)
		q.SetQuestion("test.example.", dns.TypeA)

		a, err := r.Resolve(q, ci)
		require.NoError(t, err)
		require.Len(t, a.Answer, 1)
		require.Len(t, a.Ns, 1)
		require.Len(t, a.Extra, 1)
	})
}

func TestLuaRREDNS0(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	-- Read the EDNS0 options
	opt = msg:is_edns0()
	if opt == nil then
		return nil, Error.new("no edns0")
	end

	-- Grab the options
	options = opt.option

	-- The first one should be a cookie
	if options[1].option ~= EDNS0COOKIE then
		return nil, Error.new("unexpected subnet option value in cookie option")
	end
	if options[1].cookie ~= "testing" then
		return nil, Error.new("unexpected value in edns0 cookie option")
	end

	-- The second one should be a subnet option
	if options[2].option ~= EDNS0SUBNET then
		return nil, Error.new("unexpected subnet option value in subnet option")
	end
	if options[2].family ~= 1 then
                return nil, Error.new("unexpected value in edns0 subnet option")
        end
	
	-- Reply with an extended error message
	local answer = Message.new()
	answer:set_reply(msg)
	answer.rcode = RcodeNXDOMAIN
	answer:set_edns0(4096, false)
	edns0 = answer:is_edns0()
	edns0.option = {
		EDNS0_EDE.new(15, "totally blocked"),
	}
	
	return answer, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeMX)
	q.SetEdns0(4096, false)
	edns0 := q.IsEdns0()

	edns0.Option = append(edns0.Option,
		&dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: "testing",
		},
		&dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 32,
			SourceScope:   0,
			Address:       net.ParseIP("127.0.0.1"),
		},
	)

	a, err := r.Resolve(q, ci)
	require.NoError(t, err)

	edns0 = a.IsEdns0()
	require.NotNil(t, edns0)
	require.Len(t, edns0.Option, 1)
	require.Equal(t, uint16(dns.EDNS0EDE), edns0.Option[0].Option())
	ede := edns0.Option[0].(*dns.EDNS0_EDE)
	require.Equal(t, uint16(15), ede.InfoCode)
	require.Equal(t, "totally blocked", ede.ExtraText)
}

func TestLuaSandboxBlocksIO(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	local f = io.open("/etc/passwd", "r")
	return nil, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err = r.Resolve(q, ci)
	require.Error(t, err)
}

func TestLuaSandboxBlocksOS(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	os.execute("echo pwned")
	return nil, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err = r.Resolve(q, ci)
	require.Error(t, err)
}

func TestLuaSandboxBlocksDangerousBase(t *testing.T) {
	dangerous := []struct {
		name   string
		script string
	}{
		{"loadstring", `function Resolve(msg, ci) loadstring("return 1")() return nil, nil end`},
		{"dofile", `function Resolve(msg, ci) dofile("/etc/passwd") return nil, nil end`},
		{"loadfile", `function Resolve(msg, ci) loadfile("/etc/passwd") return nil, nil end`},
		{"load", `function Resolve(msg, ci) load("return 1")() return nil, nil end`},
		{"require", `function Resolve(msg, ci) require("os") return nil, nil end`},
	}

	for _, tc := range dangerous {
		t.Run(tc.name, func(t *testing.T) {
			opt := LuaOptions{Script: tc.script}
			resolver := new(TestResolver)

			r, err := NewLua("test-lua", opt, resolver)
			if err != nil {
				// Script failed at load time (function doesn't exist), that's fine
				return
			}

			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			_, err = r.Resolve(q, ClientInfo{})
			require.Error(t, err)
		})
	}
}

func TestLuaSandboxAllowsSafeLibs(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	-- Test string library
	local s = string.upper("hello")
	if s ~= "HELLO" then
		return nil, Error.new("string.upper failed")
	end

	-- Test math library
	local n = math.floor(3.7)
	if n ~= 3 then
		return nil, Error.new("math.floor failed")
	end

	-- Test table library
	local t = {}
	table.insert(t, "a")
	if t[1] ~= "a" then
		return nil, Error.new("table.insert failed")
	end

	-- Test safe base functions
	local s2 = tostring(42)
	if s2 ~= "42" then
		return nil, Error.new("tostring failed")
	end
	if type(s2) ~= "string" then
		return nil, Error.new("type failed")
	end

	return nil, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err = r.Resolve(q, ci)
	require.NoError(t, err)
}

func TestLuaSandboxDisabled(t *testing.T) {
	opt := LuaOptions{
		NoSandbox: true,
		Script: `
function Resolve(msg, ci)
	local t = os.time()
	if t == nil or t == 0 then
		return nil, Error.new("os.time failed")
	end
	return nil, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err = r.Resolve(q, ci)
	require.NoError(t, err)
}

func TestLuaSandboxWithResolvers(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	local resolver = Resolvers[1]
	local answer, err = resolver:resolve(msg, ci)
	if err ~= nil then
		return nil, err
	end
	return answer, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	_, err = r.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 1, resolver.HitCount())
}

func TestLuaOPTOperations(t *testing.T) {
	opt := LuaOptions{
		Script: `
function Resolve(msg, ci)
	-- Set up EDNS0 and get the OPT record
	msg:set_edns0(4096, true)
	local opt = msg:is_edns0()
	if opt == nil then
		return nil, Error.new("is_edns0 returned nil")
	end

	-- Read initial values
	if opt.udp_size ~= 4096 then
		return nil, Error.new("unexpected udp_size: " .. tostring(opt.udp_size))
	end
	if opt.do_bit ~= true then
		return nil, Error.new("expected do_bit to be true")
	end
	if opt.version ~= 0 then
		return nil, Error.new("unexpected version: " .. tostring(opt.version))
	end
	if opt.extended_rcode ~= 0 then
		return nil, Error.new("unexpected extended_rcode: " .. tostring(opt.extended_rcode))
	end
	if opt.name ~= "." then
		return nil, Error.new("unexpected name: " .. opt.name)
	end
	if opt.rtype ~= TypeOPT then
		return nil, Error.new("unexpected rtype: " .. tostring(opt.rtype))
	end

	-- Modify fields
	opt.udp_size = 1232
	if opt.udp_size ~= 1232 then
		return nil, Error.new("udp_size not updated: " .. tostring(opt.udp_size))
	end

	opt.do_bit = false
	if opt.do_bit ~= false then
		return nil, Error.new("do_bit not cleared")
	end

	opt.do_bit = true
	if opt.do_bit ~= true then
		return nil, Error.new("do_bit not set")
	end

	opt.version = 1
	if opt.version ~= 1 then
		return nil, Error.new("version not updated: " .. tostring(opt.version))
	end

	-- extended_rcode stores upper 8 bits of the 12-bit RCODE (value >> 4)
	-- so we use a value >= 16 to see it reflected (e.g. BADVERS = 16)
	opt.extended_rcode = 16
	if opt.extended_rcode ~= 16 then
		return nil, Error.new("extended_rcode not updated: " .. tostring(opt.extended_rcode))
	end

	-- Test option array read/write
	opt.option = {
		EDNS0_EDE.new(15, "blocked"),
		EDNS0_COOKIE.new("testcookie"),
	}
	local options = opt.option
	if #options ~= 2 then
		return nil, Error.new("expected 2 options, got " .. tostring(#options))
	end

	-- Test OPT.new() constructor
	local newopt = OPT.new(2048, false)
	if newopt.udp_size ~= 2048 then
		return nil, Error.new("OPT.new udp_size: " .. tostring(newopt.udp_size))
	end
	if newopt.do_bit ~= false then
		return nil, Error.new("OPT.new do_bit should be false")
	end

	local newopt2 = OPT.new(512, true)
	if newopt2.udp_size ~= 512 then
		return nil, Error.new("OPT.new(512,true) udp_size: " .. tostring(newopt2.udp_size))
	end
	if newopt2.do_bit ~= true then
		return nil, Error.new("OPT.new(512,true) do_bit should be true")
	end

	-- Build the response using the modified opt record
	local answer = Message.new()
	answer:set_reply(msg)
	return answer, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	a, err := r.Resolve(q, ci)
	require.NoError(t, err)
	require.NotNil(t, a)

	// Verify the OPT record on the original message was modified
	edns0 := q.IsEdns0()
	require.NotNil(t, edns0)
	require.Equal(t, uint16(1232), edns0.UDPSize())
	require.True(t, edns0.Do())
	require.Equal(t, uint8(1), edns0.Version())
	require.Len(t, edns0.Option, 2)
	require.Equal(t, uint16(dns.EDNS0EDE), edns0.Option[0].Option())
	require.Equal(t, uint16(dns.EDNS0COOKIE), edns0.Option[1].Option())
}
