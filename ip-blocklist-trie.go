package rdns

import "net"

// Datastructure for efficient search of a list of CIDR addresses to see if
// an IP is contained in one of the CIDR ranges in the list. While it uses
// ideas from routing table implementations as described in
// https://vincent.bernat.ch/en/blog/2017-ipv4-route-lookup-linux, it differs
// in that it looks for the shortest prefix (biggest network match) since
// it's sufficient to know if an IP is covered by one of the networks.
//
// The tree sits in one flat array, a node naming its children by index rather
// than by pointer, so a list of any size costs the collector one object to mark
// rather than one per node.
type ipBlocklistTrie struct {
	nodes []ipBlocklistNode
}

// A node holds the node under each of the two values the bit at its depth can
// take. Index 0 is the root, which is nobody's child, so a zero means there is
// nothing under that bit.
//
// A leaf is the end of a network on the list. Nothing below it can matter,
// since a longer prefix inside a network already covered adds nothing, so a
// leaf has no children and says so in the slot a child index would have used.
type ipBlocklistNode struct {
	child [2]uint32
}

// Marks a node as the end of a network. Reserved as a child index, which costs
// the last of the four billion nodes a trie could otherwise hold.
const ipBlocklistLeaf = ^uint32(0)

func (n ipBlocklistNode) leaf() bool { return n.child[0] == ipBlocklistLeaf }

// Add a network to the trie.
func (t *ipBlocklistTrie) add(n *net.IPNet) {
	if len(t.nodes) == 0 {
		t.nodes = make([]ipBlocklistNode, 1) // node 0 is the root
	}
	prefix, _ := n.Mask.Size()
	p := uint32(0)
	for i := range prefix {
		if t.nodes[p].leaf() { // stop if we already have a shorter prefix than this
			break
		}
		b := bit(n.IP, i)
		if t.nodes[p].child[b] == 0 {
			t.nodes = append(t.nodes, ipBlocklistNode{})
			t.nodes[p].child[b] = uint32(len(t.nodes) - 1)
		}
		p = t.nodes[p].child[b]
	}

	// Mark this as the leaf-node. We care about the shortest prefix so nothing
	// should go past this when building the trie. Anything already below it is
	// let go of here rather than removed, and compact() drops it at the end of
	// the build.
	t.nodes[p].child = [2]uint32{ipBlocklistLeaf, 0}
}

// compact returns the trie holding only the nodes still reachable from the
// root, in the order a lookup walks them. A network added after one that
// already covers it leaves whatever was built below it unreachable, and a
// build that grew by doubling holds an array up to twice the size it needs.
func (t *ipBlocklistTrie) compact() {
	if len(t.nodes) == 0 {
		return
	}
	nodes := make([]ipBlocklistNode, 1, len(t.nodes))
	var walk func(from, to uint32)
	walk = func(from, to uint32) {
		if t.nodes[from].leaf() {
			nodes[to].child = [2]uint32{ipBlocklistLeaf, 0}
			return
		}
		for b, c := range t.nodes[from].child {
			if c == 0 {
				continue
			}
			nodes = append(nodes, ipBlocklistNode{})
			id := uint32(len(nodes) - 1)
			nodes[to].child[b] = id
			walk(c, id)
		}
	}
	walk(0, 0)
	t.nodes = nodes
}

// Returns true and the string representation of the network covering
// the IP.
func (t *ipBlocklistTrie) hasIP(ip net.IP) (string, bool) {
	if len(t.nodes) == 0 {
		return "", false
	}
	size := 32
	if addr := ip.To4(); addr == nil {
		size = 128
	} else {
		ip = addr // make sure we use the 4-byte representation of an IPv4
	}
	p := uint32(0)
	for i := 0; i < size; i++ {
		n := t.nodes[p]
		if n.leaf() {
			return ruleString(ip, i), true
		}
		p = n.child[bit(ip, i)]
		if p == 0 {
			return "", false
		}
	}
	return ruleString(ip, size), true
}

func ruleString(ip net.IP, maskBits int) string {
	size := 32
	if addr := ip.To4(); addr == nil {
		size = 128
	}
	mask := net.CIDRMask(maskBits, size)
	ipNet := &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}
	return ipNet.String()
}

// Returns n'th bit from an IP address from the left.
func bit(ip net.IP, n int) int {
	return int(ip[n/8]>>(7-n%8)) & 1
}
