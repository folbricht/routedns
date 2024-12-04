package rdns

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// MACDB holds a list of MAC addresses used to clients with the given MAC (as per
// EDNS0 option 65001).
type MACDB struct {
	name   string
	loader BlocklistLoader
	macs   [][]byte // TODO: for large lists, a trie would be more efficient
}

var _ BlocklistDB = &MACDB{}

// NewMACDB returns a new instance of a matcher for a list of MAC addresses.
func NewMACDB(name string, loader BlocklistLoader) (*MACDB, error) {
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	db := &MACDB{
		name:   name,
		macs:   make([][]byte, 0, len(rules)),
		loader: loader,
	}
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "#") || r == "" {
			continue
		}
		mac, err := parseMAC(r)
		if err != nil {
			return nil, err
		}
		db.macs = append(db.macs, mac)
	}
	return db, nil
}

func (m *MACDB) Reload() (BlocklistDB, error) {
	return NewMACDB(m.name, m.loader)
}

func (m *MACDB) Match(msg *dns.Msg) ([]net.IP, []string, *BlocklistMatch, bool) {
	// Do we have an EDNS0 record?
	edns0 := msg.IsEdns0()
	if edns0 == nil {
		return nil, nil, nil, false
	}

	// Check if there's an option 65001 in it
	var opt65001 []byte
	for _, opt := range edns0.Option {
		// Option 65001 is currently decoded into *dns.EDNS0_LOCAL. This
		// will break when/if it's standardized and gets a dedicate type.
		local, ok := opt.(*dns.EDNS0_LOCAL)
		if !ok {
			continue
		}
		if local.Code != 65001 {
			continue
		}
		if len(local.Data) != 6 { // Not a MAC?
			continue
		}
		opt65001 = local.Data
	}

	// Did we find a EDNS0 record with option 65001
	if len(opt65001) != 6 {
		return nil, nil, nil, false
	}

	// Match against the MAC addresses on the blocklist
	for _, mac := range m.macs {
		if bytes.Equal(mac, opt65001) {
			return nil, nil, &BlocklistMatch{List: m.name, Rule: hex.EncodeToString(mac)}, true
		}

	}
	return nil, nil, nil, false
}

func (m *MACDB) Close() error {
	return nil
}

func (m *MACDB) String() string {
	return "MAC-blocklist"
}

// ParseMAC decodes a MAC address given in the format 01:23:45:ab:cd:ef to
// an array of 6 bytes.
func parseMAC(addr string) ([]byte, error) {
	b := []byte(addr)
	if len(b) != 17 { // check total length
		return nil, fmt.Errorf("unable to parse mac address %q, expected format 01:23:45:ab:cd:ef", addr)
	}
	// Check the format, we need 6 parts with 5 separator characters (:) in it
	for i := 0; i < 5; i++ {
		if b[(i*3)+2] != ':' {
			return nil, fmt.Errorf("unable to parse mac address %q, expected format 01:23:45:ab:cd:ef", addr)
		}
	}
	b = bytes.ReplaceAll(b, []byte{':'}, nil)
	out := make([]byte, 6)
	n, err := hex.Decode(out[:], b)
	if err != nil || n != 6 {
		return nil, fmt.Errorf("unable to parse mac address %q, expected format 01:23:45:ab:cd:ef", addr)
	}
	return out, nil
}
