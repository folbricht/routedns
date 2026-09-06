package rdns

import (
	"bytes"
	"math/rand"
	"net"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// DomainCompactDB matches the same rules as DomainDB, in the same way, but
// stores them as fingerprints rather than as labels. It holds one 8 byte entry
// per node of the trie DomainDB would build and no label bytes at all, which is
// around a quarter of the memory.
//
// What that costs is a name nobody listed whose fingerprint equals one that is,
// which is then answered as though a rule covered it. With 60 bits of
// fingerprint the odds are the entry count over 2^60 for each label looked up,
// so about one query in 800 billion against a 274k rule list and one in 140
// billion against a 2M rule one. A name that is on the list can never be
// missed, since it always hashes to its own entry and entries only gain flags.
// The seed changes on every load, so a collision does not survive a refresh
// and cannot be arranged in advance. See doc/blocklists.md for the rarer case
// where the node that collides is one queries pass through rather than end on.
//
// The rule syntax and the matching are exactly DomainDB's, see there.
type DomainCompactDB struct {
	name              string
	fingerprints      domainFingerprints
	loader            BlocklistLoader
	includeSubdomains bool
}

// domainFingerprints is one entry per node, holding a fingerprint of the suffix
// that node stands for and the flags of the rules that end on it. Entries are
// sorted, and an index over the top bits of the fingerprint says where each
// bucket of them starts, so a lookup reads the index and then, almost always, a
// single cache line of entries.
//
// Nothing here is a pointer and no labels are kept, so the whole database is
// two objects for the garbage collector whatever the list holds.
type domainFingerprints struct {
	entries []uint64 // fingerprint<<4 | flags, ascending
	index   []uint32 // bucket -> first entry
	shift   uint     // fingerprint >> shift = bucket
	seed    uint64   // per build, so a collision is not the same twice
}

// The flags live in the low four bits of an entry, leaving 60 for the
// fingerprint.
const (
	domainFlagBits = 4
	domainFlagMask = 1<<domainFlagBits - 1
)

var _ BlocklistDB = &DomainCompactDB{}

// NewDomainCompactDB returns a matcher for a list of domain rules that trades
// exactness for memory. See DomainCompactDB.
func NewDomainCompactDB(name string, loader BlocklistLoader) (*DomainCompactDB, error) {
	return newDomainCompactDB(name, loader, false)
}

// NewDomainSubdomainCompactDB is like NewDomainCompactDB but treats bare
// entries as matching the apex and all sub-domains, as NewDomainSubdomainDB
// does.
func NewDomainSubdomainCompactDB(name string, loader BlocklistLoader) (*DomainCompactDB, error) {
	return newDomainCompactDB(name, loader, true)
}

func newDomainCompactDB(name string, loader BlocklistLoader, includeSubdomains bool) (*DomainCompactDB, error) {
	f := domainFingerprints{seed: rand.Uint64()}
	var entries []uint64
	recent := new(domainRecent)
	reset := func() {
		entries, recent = entries[:0], new(domainRecent)
	}
	err := domainRules(loader, includeSubdomains, reset, func(domain string, flag uint8) error {
		// Walk the labels from the TLD inwards, hashing each suffix as it goes.
		// Every node above the last one has a child by definition, which is
		// what lets a query stop as soon as it reaches a node without one.
		h := f.seed
		end := len(domain)
		for {
			i := strings.LastIndexByte(domain[:end], '.')
			h = domainSuffixHash(h, domain[i+1:end])
			e := domainEntry(h, ruleHasChildren)
			if i <= 0 {
				e = domainEntry(h, flag)
			}
			if !recent.seen(e) {
				entries = append(entries, e)
			}
			if i <= 0 {
				break
			}
			end = i
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	f.build(entries)
	return &DomainCompactDB{name, f, loader, includeSubdomains}, nil
}

func (m *DomainCompactDB) Reload() (BlocklistDB, error) {
	return newDomainCompactDB(m.name, m.loader, m.includeSubdomains)
}

func (m *DomainCompactDB) Match(msg *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	var buf [maxDomainName]byte
	return m.match(domainQueryName(msg, buf[:]))
}

// match walks the labels of a lower-cased query name from the TLD inwards,
// stopping at the first rule that covers it, exactly as DomainDB does. The
// difference is only in what identifies a node: the hash of the suffix so far
// rather than an index into an array of them.
func (m *DomainCompactDB) match(name []byte) ([]net.IP, []string, *BlocklistMatch, bool) {
	h := m.fingerprints.seed
	flags := m.fingerprints.rootFlags()
	end := len(name)
	for end > 0 {
		if flags&ruleHasChildren == 0 {
			return nil, nil, nil, false // nothing more specific exists
		}
		i := bytes.LastIndexByte(name[:end], '.')
		h = domainSuffixHash(h, name[i+1:end])
		var ok bool
		flags, ok = m.fingerprints.find(h)
		if !ok {
			return nil, nil, nil, false
		}
		if prefix, ok := domainRuleAt(flags, i > 0); ok {
			return nil, nil, domainMatched(m.name, prefix, name[i+1:]), true
		}
		end = i
	}
	if flags&ruleExact != 0 {
		return nil, nil, domainMatched(m.name, "", name), true
	}
	return nil, nil, nil, false
}

func (m *DomainCompactDB) String() string {
	return "Domain-Compact"
}

// Half of what a build appends is a node some earlier rule already recorded,
// and the busiest of those are the handful of top level domains that every rule
// passes through: a two million rule list walks over "com" a million times.
// domainRecent is a direct-mapped cache of the entries just written, which
// catches most of those before they reach the slice that has to be sorted.
// Dropping a repeat is always safe, since entries carrying the same flags merge
// into one and a second copy adds nothing.
type domainRecent [1 << 12]uint64

// seen reports whether entry was written recently, and records it if not. An
// entry always carries at least one flag, so it is never zero and an untouched
// slot cannot look like a hit.
func (r *domainRecent) seen(entry uint64) bool {
	slot := &r[entry>>domainFlagBits&uint64(len(r)-1)]
	if *slot == entry {
		return true
	}
	*slot = entry
	return false
}

// domainSuffixHash folds one more label into the hash of the suffix to its
// right. The separator keeps "ab.c" apart from "a.bc".
func domainSuffixHash[T labelText](h uint64, label T) uint64 {
	for i := 0; i < len(label); i++ {
		h ^= uint64(label[i])
		h *= fnvPrime64
	}
	h ^= '.'
	return h * fnvPrime64
}

// domainEntry is the stored form of a node: the avalanched hash of its suffix
// with the flags in the bits the fingerprint gives up.
func domainEntry(h uint64, flags uint8) uint64 {
	return avalanche64(h)>>domainFlagBits<<domainFlagBits | uint64(flags)
}

// build sorts the entries, merges the ones that describe the same node, and
// indexes them by the top bits of their fingerprint.
func (f *domainFingerprints) build(entries []uint64) {
	slices.Sort(entries)

	// A node is recorded once per rule that passes through it, so the same
	// fingerprint arrives many times over. Fold those into one entry holding
	// every flag they carried.
	merged := entries[:0]
	for _, e := range entries {
		if n := len(merged); n > 0 && merged[n-1]>>domainFlagBits == e>>domainFlagBits {
			merged[n-1] |= e & domainFlagMask
			continue
		}
		merged = append(merged, e)
	}
	// Clone rather than keep the slice the unmerged entries were appended to,
	// which is twice the size the merged ones need.
	f.entries = slices.Clone(merged)

	// Aim for eight entries per bucket, which is one cache line of them.
	buckets := 8
	for buckets*8 < len(f.entries) {
		buckets <<= 1
	}
	f.shift = 64 - domainBucketBits(buckets)
	f.index = make([]uint32, buckets+1)
	e := 0
	for b := range buckets {
		f.index[b] = uint32(e)
		for e < len(f.entries) && int(f.entries[e]>>f.shift) == b {
			e++
		}
	}
	f.index[buckets] = uint32(len(f.entries))
}

func domainBucketBits(buckets int) uint {
	var bits uint
	for 1<<bits < buckets {
		bits++
	}
	return bits
}

// rootFlags says whether the list holds anything at all, in the same shape the
// walk reads every other node in.
func (f *domainFingerprints) rootFlags() uint8 {
	if len(f.entries) == 0 {
		return 0
	}
	return ruleHasChildren
}

// find returns the flags recorded for a suffix, and whether it is on the list.
func (f *domainFingerprints) find(h uint64) (uint8, bool) {
	want := domainEntry(h, 0)
	bucket := want >> f.shift
	for i := f.index[bucket]; i < f.index[bucket+1]; i++ {
		e := f.entries[i]
		switch {
		case e&^domainFlagMask == want:
			return uint8(e) & domainFlagMask, true
		case e > want:
			return 0, false // entries are sorted, it cannot be further on
		}
	}
	return 0, false
}
