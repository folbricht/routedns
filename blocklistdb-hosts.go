package rdns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// HostsDB holds a list of hosts-file entries that are used in blocklists to spoof or bloc requests.
// IP4 and IP6 records can be spoofed independently, however it's not possible to block only one type. If
// IP4 is given but no IP6, then a domain match will still result in an NXDOMAIN for the IP6 address.
type HostsDB struct {
	name    string
	filters map[string]ipRecords
	ptrMap  map[string]string // PTR lookup map
	loader  BlocklistLoader
}

type ipRecords struct {
	ip4 net.IP
	ip6 net.IP
}

var _ BlocklistDB = &HostsDB{}

// NewHostsDB returns a new instance of a matcher for a list of regular expressions.
func NewHostsDB(name string, loader BlocklistLoader) (*HostsDB, error) {
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	filters := make(map[string]ipRecords)
	ptrMap := make(map[string]string)
	for _, r := range rules {
		r = strings.TrimSpace(r)
		fields := strings.Fields(r)
		if len(fields) == 0 {
			continue
		}
		ipString := fields[0]
		names := fields[1:]
		if strings.HasPrefix(ipString, "#") {
			continue
		}
		if len(names) == 0 {
			continue
		}
		ip := net.ParseIP(ipString)
		var isIP4 bool
		if ip4 := ip.To4(); len(ip4) == net.IPv4len {
			isIP4 = true
		}
		if ip.IsUnspecified() {
			ip = nil
		}
		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			ips := filters[name]
			if isIP4 {
				ips.ip4 = ip
			} else {
				ips.ip6 = ip
			}
			filters[name] = ips
		}
		reverseAddr, err := dns.ReverseAddr(ipString)
		if err != nil {
			continue
		}
		ptrMap[reverseAddr] = names[0]
	}
	return &HostsDB{name, filters, ptrMap, loader}, nil
}

func (m *HostsDB) Reload() (BlocklistDB, error) {
	return NewHostsDB(m.name, m.loader)
}

func (m *HostsDB) Match(q dns.Question) (net.IP, string, *BlocklistMatch, bool) {
	if q.Qtype == dns.TypePTR {
		name, ok := m.ptrMap[q.Name]
		return nil, name, &BlocklistMatch{
			List: m.name,
			Rule: name,
		}, ok
	}
	name := strings.TrimSuffix(q.Name, ".")
	ips, ok := m.filters[name]
	if q.Qtype == dns.TypeA {
		return ips.ip4,
			"",
			&BlocklistMatch{
				List: m.name,
				Rule: ips.ip4.String() + " " + name,
			},
			ok
	}
	return ips.ip6,
		"",
		&BlocklistMatch{
			List: m.name,
			Rule: ips.ip6.String() + " " + name,
		},
		ok
}

func (m *HostsDB) String() string {
	return "Hosts"
}
