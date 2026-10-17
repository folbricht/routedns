//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"fmt"

	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

// Message functions

func luaMessageType() []lua.Option {
	return []lua.Option{
		lua.Type[dns.Msg](
			// The header flags are fields of their own: id, response, rcode,
			// recursion_desired, recursion_available, authoritative and
			// authenticated_data. The sections are converted in __index.
			lua.Writable("Id", "Response", "Rcode", "RecursionDesired", "RecursionAvailable", "Authoritative", "AuthenticatedData"),
			lua.Hide("Opcode", "Truncated", "Zero", "CheckingDisabled", "Compress", "Question", "Answer", "Ns", "Extra"),
			lua.Meta("__index", func(c *lua.Call) error {
				msg := c.Arg[*dns.Msg](0)
				switch fieldName := c.Arg[string](1); fieldName {
				case "questions":
					// The questions are the message's own, so a script can
					// change them in place
					table := lua.NewTable(len(msg.Question), 0)
					for i := range msg.Question {
						table.Set(lua.Int(int64(i+1)), lua.ValueOf(&msg.Question[i]))
					}
					return c.Return(table)
				case "answer":
					return c.Return(rrSliceToTable(msg.Answer))
				case "ns":
					return c.Return(rrSliceToTable(msg.Ns))
				case "extra":
					return c.Return(rrSliceToTable(msg.Extra))
				default:
					return c.ArgError(1, fmt.Sprintf("message does not have field %q", fieldName))
				}
			}),
			lua.Meta("__newindex", func(c *lua.Call) error {
				msg := c.Arg[*dns.Msg](0)
				switch fieldName := c.Arg[string](1); fieldName {
				case "questions":
					questions, err := luaArray[*dns.Question](c.Value(2))
					if err != nil {
						return c.ArgError(2, err.Error())
					}
					msg.Question = make([]dns.Question, 0, len(questions))
					for _, q := range questions {
						msg.Question = append(msg.Question, *q)
					}
				case "answer":
					return setRRSlice(c, &msg.Answer)
				case "ns":
					return setRRSlice(c, &msg.Ns)
				case "extra":
					return setRRSlice(c, &msg.Extra)
				default:
					return c.ArgError(1, fmt.Sprintf("message does not have field %q", fieldName))
				}
				return nil
			}),
			lua.Method("set_reply", func(c *lua.Call) error {
				msg := c.Arg[*dns.Msg](0)
				msg.SetReply(c.Arg[*dns.Msg](1))
				return c.Return(msg)
			}),
			lua.Method("set_question", func(c *lua.Call) error {
				msg := c.Arg[*dns.Msg](0)
				msg.SetQuestion(c.Arg[string](1), c.Arg[uint16](2))
				return c.Return(msg)
			}),
			lua.Method("is_edns0", func(c *lua.Call) error {
				return c.Return(c.Arg[*dns.Msg](0).IsEdns0())
			}),
			lua.Method("set_edns0", func(c *lua.Call) error {
				msg := c.Arg[*dns.Msg](0)
				msg.SetEdns0(c.Arg[uint16](1), c.Arg[bool](2))
				return c.Return(msg)
			}),
		),
		// static attributes
		lua.Module("Message", lua.Members{
			"new": lua.GoFunc(func(c *lua.Call) error {
				return c.Return(new(dns.Msg))
			}),
		}),
	}
}

func rrSliceToTable(rrs []dns.RR) *lua.Table {
	return luaTable(rrs, luaRRValue)
}

// setRRSlice sets a section of a message to the array of records being
// assigned to it.
func setRRSlice(c *lua.Call, section *[]dns.RR) error {
	values, err := luaArray[lua.Value](c.Value(2))
	if err != nil {
		return c.ArgError(2, err.Error())
	}
	rrs := make([]dns.RR, 0, len(values))
	for _, v := range values {
		rr, err := luaRRArg(v)
		if err != nil {
			return c.ArgError(2, err.Error())
		}
		rrs = append(rrs, rr)
	}
	*section = rrs
	return nil
}
