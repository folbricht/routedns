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
		fields := strings.Fields(r)
		if len(fields) == 0 {
			return nil
		}
		ipString := fields[0]
		names := fields[1:]
		if strings.HasPrefix(ipString, "#") {
			return nil
		}
		if len(names) == 0 {
			return nil
		}
		ip := net.ParseIP(ipString)

		// A name pointed at an unspecified address has no address to answer
		// with, so it can only block. No reverse entry is made for it either:
		// every such name shares the one reverse address, and a PTR lookup of
		// it would answer with an arbitrary handful of the whole list.
		if ip.IsUnspecified() {
			for _, name := range names {
				// A label longer than a label may be could never be reached by
				// a query, and the trie stores a label's length in a byte, so
				// such a name is skipped rather than truncated into a rule that
				// matches something else.
				name = hostsName(name)
				if name == "" || hasOverlongLabel(name) {
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
		ptrMap[reverseAddr] = append(ptrMap[reverseAddr], names...)
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
