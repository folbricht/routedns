//go:build !nolua

package rdns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// threeRecordResolver answers with three fresh A records, so a script that
// walks the answer has something to walk.
type threeRecordResolver struct{}

func (threeRecordResolver) Resolve(q *dns.Msg, _ ClientInfo) (*dns.Msg, error) {
	a := new(dns.Msg)
	a.SetReply(q)
	for i := range 3 {
		a.Answer = append(a.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.IPv4(192, 0, 2, byte(i+1)),
		})
	}
	return a, nil
}

func (threeRecordResolver) String() string { return "threeRecordResolver()" }

var luaBenchScripts = map[string]string{
	"Passthrough": `
function Resolve(msg, ci)
	return Resolvers[1]:resolve(msg, ci)
end`,
	"TTLClamp": `
function Resolve(msg, ci)
	local answer, err = Resolvers[1]:resolve(msg, ci)
	if err ~= nil then
		return nil, err
	end
	for _, rr in ipairs(answer.answer) do
		if rr.ttl > 300 then
			rr.ttl = 300
		end
	end
	return answer, nil
end`,
	"RouteByName": `
function Resolve(msg, ci)
	local name = msg.questions[1].name
	if string.find(name, "%.example%.net%.$") then
		return Resolvers[2]:resolve(msg, ci)
	end
	return Resolvers[1]:resolve(msg, ci)
end`,
}

func newLuaBench(b *testing.B, name string) (*Lua, *dns.Msg) {
	r, err := NewLua("bench", LuaOptions{Script: luaBenchScripts[name]}, threeRecordResolver{}, threeRecordResolver{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(r.Close)
	q := new(dns.Msg)
	q.SetQuestion("host.example.com.", dns.TypeA)
	return r, q
}

func benchLua(b *testing.B, name string) {
	r, q := newLuaBench(b, name)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.Resolve(q, ClientInfo{}); err != nil {
			b.Fatal(err)
		}
	}
}

func benchLuaParallel(b *testing.B, name string) {
	r, q := newLuaBench(b, name)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := r.Resolve(q, ClientInfo{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkLuaPassthrough(b *testing.B)         { benchLua(b, "Passthrough") }
func BenchmarkLuaTTLClamp(b *testing.B)            { benchLua(b, "TTLClamp") }
func BenchmarkLuaRouteByName(b *testing.B)         { benchLua(b, "RouteByName") }
func BenchmarkLuaPassthroughParallel(b *testing.B) { benchLuaParallel(b, "Passthrough") }
func BenchmarkLuaTTLClampParallel(b *testing.B)    { benchLuaParallel(b, "TTLClamp") }
func BenchmarkLuaRouteByNameParallel(b *testing.B) { benchLuaParallel(b, "RouteByName") }
