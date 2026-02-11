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
