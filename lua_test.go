package rdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLuaSimplePassthrough(t *testing.T) {
	opt := LuaOptions{
		Script: `
function resolve(msg, ci)
	resolver = Resolvers[1]
	answer, err = resolver:resolve(msg, ci)
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
function resolve(msg, ci)
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
	opt := LuaOptions{
		Script: `
function resolve(msg, ci)
	answer = Message.new()
	question = Question.new()
	question:set_name("example.com.")
	answer:set_question({question})
	return answer, nil
end`,
	}

	var ci ClientInfo
	resolver := new(TestResolver)

	r, err := NewLua("test-lua", opt, resolver)
	require.NoError(t, err)

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)

	answer, err := r.Resolve(q, ci)
	require.NoError(t, err)
	require.Equal(t, 0, resolver.HitCount())
	require.Equal(t, "example.com.", answer.Question[0].Name)
}
