package rdns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// HostsDB holds a list of hosts-file entries that are used in blocklists to spoof or block requests.
// IP4 and IP6 records can be spoofed independently, however it's not possible to block only one type. If
// IP4 is given but no IP6, then a domain match will still result in an NXDOMAIN for the IP6 address.
//
// Names pointed at an unspecified address have nothing to spoof and only ever
// block, which is what a hosts-format blocklist is made of. Those are held in a
// trie of labels rather than a map of names, the same structure the domain
// formats use, so a list of that shape costs a fraction of the memory and
// nothing per rule for the garbage collector to walk. The map holds only the
// names that carry an address to answer with.
type HostsDB struct {
	name    string
	blocked domainTrie
	filters map[string]ipRecords
	ptrMap  map[string][]string // PTR lookup map
	loader  BlocklistLoader
}

// Max number of A/AAAA records created for hosts blocklist
const maxHostsResponses = 10

type ipRecords struct {
	ip4 []net.IP
	ip6 []net.IP
}

var _ BlocklistDB = &HostsDB{}

// NewHostsDB returns a new instance of a matcher for a list of hosts-file entries.
func NewHostsDB(name string, loader BlocklistLoader) (*HostsDB, error) {
	b := newDomainBuilder()
	filters := make(map[string]ipRecords)
	ptrMap := make(map[string][]string)
	// Fresh structures rather than clear(), which empties a map without giving
	// up the buckets it grew from a list that broke off.
	reset := func() {
		b = newDomainBuilder()
		filters = make(map[string]ipRecords)
		ptrMap = make(map[string][]string)
	}
	err := loader.Load(reset, func(r string) error {
		// A line is an address followed by the names it answers for, and a
		// comment can begin anywhere on it. Everything from the comment on is
		// dropped rather than read as more names, which is what a hosts file
		// means by it and what stopped a list carrying "0.0.0.0 ads.example.com
		// # tracker" from also blocking "tracker".
		fields := strings.Fields(r)
		for i, f := range fields {
			if strings.HasPrefix(f, "#") {
				fields = fields[:i]
				break
			}
		}
		if len(fields) < 2 {
			return nil
		}
		ipString := fields[0]
		names := fields[1:]

		// A line whose first field is not an address is not a hosts entry, so
		// the words on it are not names. A list opening with an un-commented
		// "This list is provided as is" would otherwise answer NXDOMAIN for
		// "list", "is", "provided" and "as".
		ip := net.ParseIP(ipString)
		if ip == nil {
			return nil
		}

		// A name pointed at an unspecified address has no address to answer
		// with, so it can only block. No reverse entry is made for it either:
		// every such name shares the one reverse address, and a PTR lookup of
		// it would answer with an arbitrary handful of the whole list.
		if ip.IsUnspecified() {
			for _, name := range names {
				// Two shapes are skipped rather than recorded, because the trie
				// would file them under a name the list never carried. A label
				// longer than a label may be has its length stored in a byte and
				// would wrap, and a leading dot is dropped by the walk, which
				// would turn the malformed ".example.com" into a rule against
				// the apex. Neither could be queried in the map this replaced.
				name = hostsName(name)
				if name == "" || name[0] == '.' || hasOverlongLabel(name) {
					continue
				}
				if err := b.add(name, ruleExact); err != nil {
					return err
				}
			}
			return nil
		}

		var isIP4 bool
		if ip4 := ip.To4(); len(ip4) == net.IPv4len {
			isIP4 = true
		}
		for _, name := range names {
			name = hostsName(name)
			ips := filters[name]
			if isIP4 {
				if len(ips.ip4) > maxHostsResponses {
					continue
				}
				ips.ip4 = append(ips.ip4, ip)
			} else {
				if len(ips.ip6) > maxHostsResponses {
					continue
				}
				ips.ip6 = append(ips.ip6, ip)
			}
			filters[name] = ips
		}
		reverseAddr, err := dns.ReverseAddr(ipString)
		if err != nil {
			return nil
		}
		// One address covers every name a list points at it, and a PTR query is
		// answered with maxPTRResponses of them, so the rest are only held. A
		// list that sinkholes to 127.0.0.1 rather than to an unspecified address
		// would otherwise gather all of its names under the one entry.
		if have := len(ptrMap[reverseAddr]); have < maxPTRResponses {
			ptrMap[reverseAddr] = append(ptrMap[reverseAddr], names[:min(len(names), maxPTRResponses-have)]...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &HostsDB{name, b.done(), filters, ptrMap, loader}, nil
}

// hostsName returns a name from a hosts-file entry in the form queries are
// matched in: lower case and without a trailing dot.
func hostsName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func (m *HostsDB) Reload() (BlocklistDB, error) {
	return NewHostsDB(m.name, m.loader)
}

func (m *HostsDB) Match(msg *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	q := msg.Question[0]
	if q.Qtype == dns.TypePTR {
		names, ok := m.ptrMap[strings.ToLower(q.Name)]
		if !ok {
			return nil, nil, nil, false
		}
		var rule string
		if len(names) > 0 {
			rule = names[0]
		}
		return nil, names, &BlocklistMatch{List: m.name, Rule: rule}, true
	}

	var buf [maxDomainName]byte
	name := domainQueryName(msg, buf[:])

	// A name can carry both an address to spoof and a bare block rule, and the
	// address is the more specific answer, so the map is looked up first.
	if ips, ok := m.filters[string(name)]; ok {
		addr := ips.ip6
		if q.Qtype == dns.TypeA {
			addr = ips.ip4
		}
		return addr, nil, &BlocklistMatch{List: m.name, Rule: string(name)}, true
	}
	if _, rule, ok := trieMatch(&m.blocked, name); ok {
		return nil, nil, domainMatched(m.name, "", rule), true
	}
	return nil, nil, nil, false
}

func (m *HostsDB) String() string {
	return "Hosts"
}
