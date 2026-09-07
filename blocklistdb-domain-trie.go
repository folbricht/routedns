package rdns

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"
)

// The longest label a domain name can carry. A rule with anything longer could
// never be reached by a valid query.
const maxDomainLabel = 63

// A slot in the lookup table packs the three things a probe needs into one
// word: the parent it hangs under, the child it points at, and a byte of the
// hash to reject a mismatch before reading the child's label. A node index is
// therefore 28 bits wide, and index 0 is the root, which is nobody's child, so
// a filled slot is never zero.
const (
	domainNodeBits   = 28
	maxDomainNodes   = 1 << domainNodeBits
	domainSlotParent = 64 - domainNodeBits
	domainSlotKey    = uint64(maxDomainNodes-1)<<domainSlotParent | 0xff // parent and tag
	domainSlotChild  = maxDomainNodes - 1
)

func domainSlot(parent, child uint32, tag uint8) uint64 {
	return uint64(parent)<<domainSlotParent | uint64(child)<<8 | uint64(tag)
}

// labelText is a domain label as its two callers hold it: a string while the
// rules are read, a slice of the lower-cased query while a name is matched.
// Neither is converted to the other, so neither path allocates.
type labelText interface{ ~string | ~[]byte }

const (
	fnvOffsetBasis64 = 14695981039346656037
	fnvPrime64       = 1099511628211
	goldenRatio64    = 0x9e3779b97f4a7c15 // spreads a node index over the word
)

// domainHash hashes a label together with the node it hangs under, so that the
// same label below two parents lands in two different places.
//
// The loop is FNV-1a, but this is not hash/fnv and cannot be swapped for it. It
// starts from the parent mixed into the offset basis rather than the basis
// alone, which keys the hash on the pair without encoding the two into bytes
// first, and it ends in a finalizer because the two ends of the result are read
// separately: the table index is taken off the top of the word by bits.Mul64,
// where FNV-1a is weakest, and the tag stored in a slot off the bottom.
func domainHash[T labelText](parent uint32, label T) uint64 {
	h := uint64(parent)*goldenRatio64 ^ fnvOffsetBasis64
	for i := 0; i < len(label); i++ {
		h ^= uint64(label[i])
		h *= fnvPrime64
	}
	return avalanche64(h)
}

// avalanche64 is splitmix64's finalizer, which spreads every input bit over the
// whole word.
func avalanche64(h uint64) uint64 {
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	return h ^ h>>31
}

// index maps a hash onto the table without a division.
func (t *domainTrie) index(h uint64) uint64 {
	idx, _ := bits.Mul64(h, uint64(len(t.slots)))
	return idx
}

func (t *domainTrie) next(idx uint64) uint64 {
	idx++
	if idx == uint64(len(t.slots)) {
		return 0
	}
	return idx
}

// labelAt returns a node's label, from the node itself or from the blob.
func (t *domainTrie) labelAt(node uint32) []byte {
	n := &t.nodes[node]
	if n.length <= domainInlineLabel {
		return n.label[:n.length]
	}
	off := binary.LittleEndian.Uint32(n.label[:4])
	return t.blob[off : off+uint32(n.length)]
}

// trieFind returns the child of parent carrying the given label. A slot is
// accepted only once its parent and its label both match what was asked for,
// which the hash never stands in for, so a hash collision costs a comparison
// rather than a wrong answer. The byte of hash in the slot is there to settle
// most mismatches without reading the label at all.
func trieFind[T labelText](t *domainTrie, parent uint32, label T) (uint32, bool) {
	h := domainHash(parent, label)
	key := domainSlot(parent, 0, uint8(h))
	idx := t.index(h)
	for {
		s := t.slots[idx]
		if s == 0 {
			return 0, false
		}
		if s&domainSlotKey == key {
			node := uint32(s>>8) & domainSlotChild
			if labelEqual(t.labelAt(node), label) {
				return node, true
			}
		}
		idx = t.next(idx)
	}
}

// trieAdd records node as the child of parent under the given label. The
// caller has established that it isn't there yet.
func trieAdd[T labelText](t *domainTrie, parent uint32, label T, node uint32) {
	h := domainHash(parent, label)
	idx := t.index(h)
	for t.slots[idx] != 0 {
		idx = t.next(idx)
	}
	t.slots[idx] = domainSlot(parent, node, uint8(h))
}

func labelEqual[T labelText](stored []byte, label T) bool {
	if len(stored) != len(label) {
		return false
	}
	for i := range stored {
		if stored[i] != label[i] {
			return false
		}
	}
	return true
}

// domainBuilder fills a trie one rule at a time. It keeps the parent of every
// node so the table can be rebuilt as it grows, and drops that once the trie
// is finished.
type domainBuilder struct {
	domainTrie
	parents []uint32
}

func newDomainBuilder() *domainBuilder {
	b := &domainBuilder{}
	b.nodes = make([]domainNode, 1) // node 0 is the root
	b.parents = make([]uint32, 1)
	b.rebuild(64)
	return b
}

// domainTableSize is the table a trie of n nodes wants. Linear probing degrades
// sharply as a table fills, and two thirds is where the probe runs are still
// short enough that a lookup rarely leaves the cache line it starts on.
func domainTableSize(nodes uint64) uint64 {
	return nodes * 3 / 2
}

// child returns the node for label under parent, adding it if it's new.
func (b *domainBuilder) child(parent uint32, label string) (uint32, error) {
	if node, ok := trieFind(&b.domainTrie, parent, label); ok {
		return node, nil
	}
	if len(b.nodes) >= maxDomainNodes {
		return 0, fmt.Errorf("blocklist has more than %d labels", maxDomainNodes)
	}
	if uint64(len(b.nodes)+1)*3 > uint64(len(b.slots))*2 {
		b.rebuild(uint64(len(b.slots)) * 2)
	}
	node := domainNode{length: uint8(len(label))}
	if len(label) <= domainInlineLabel {
		copy(node.label[:], label)
	} else {
		binary.LittleEndian.PutUint32(node.label[:4], uint32(len(b.blob)))
		b.blob = append(b.blob, label...)
	}
	id := uint32(len(b.nodes))
	b.nodes = append(b.nodes, node)
	b.parents = append(b.parents, parent)
	b.nodes[parent].flags |= ruleHasChildren
	trieAdd(&b.domainTrie, parent, label, id)
	return id, nil
}

// rebuild lays the table out again at the given size.
func (b *domainBuilder) rebuild(size uint64) {
	b.slots = make([]uint64, size)
	for id := 1; id < len(b.nodes); id++ {
		trieAdd(&b.domainTrie, b.parents[id], b.labelAt(uint32(id)), uint32(id))
	}
}

// done returns the finished trie, sized to what it holds rather than to the
// doubling it grew by, which it would otherwise hold while it serves queries.
func (b *domainBuilder) done() domainTrie {
	if want := domainTableSize(uint64(len(b.nodes))) + 8; uint64(len(b.slots)) > want*4/3 {
		b.rebuild(want)
	}
	if cap(b.nodes) > len(b.nodes)+len(b.nodes)/3+8 {
		b.nodes = slices.Clone(b.nodes)
	}
	if cap(b.blob) > len(b.blob)+len(b.blob)/3 {
		b.blob = slices.Clone(b.blob)
	}
	b.parents = nil
	return b.domainTrie
}
