//go:build !nolua && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)

package rdns

import (
	"strings"

	lua "github.com/folbricht/glua"
	"github.com/miekg/dns"
)

func luaConstants() []lua.Option {
	// Register build version
	opts := []lua.Option{lua.Global("BuildVersion", CurrentBuild().Version)}

	// Register TypeA, TypeAAAA, etc. Skip the names that can't be Lua
	// identifiers, like NSAP-PTR.
	for value, name := range dns.TypeToString {
		if strings.Contains(name, "-") {
			continue
		}
		opts = append(opts, lua.Global("Type"+name, int64(value)))
	}

	// Register ClassIN, etc
	for value, name := range dns.ClassToString {
		opts = append(opts, lua.Global("Class"+name, int64(value)))
	}

	// Register Rcodes, RcodeNOERROR, RcodeNXDOMAIN, etc
	for value, name := range dns.RcodeToString {
		opts = append(opts, lua.Global("Rcode"+name, int64(value)))
	}

	// Register EDNS0 option codes
	for name, value := range map[string]uint16{
		"EDNS0LLQ":          0x1,
		"EDNS0UL":           0x2,
		"EDNS0NSID":         0x3,
		"EDNS0ESU":          0x4,
		"EDNS0DAU":          0x5,
		"EDNS0DHU":          0x6,
		"EDNS0N3U":          0x7,
		"EDNS0SUBNET":       0x8,
		"EDNS0EXPIRE":       0x9,
		"EDNS0COOKIE":       0xa,
		"EDNS0TCPKEEPALIVE": 0xb,
		"EDNS0PADDING":      0xc,
		"EDNS0EDE":          0xf,
	} {
		opts = append(opts, lua.Global(name, int64(value)))
	}
	return opts
}
