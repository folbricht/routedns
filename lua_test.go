package rdns

import (
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
