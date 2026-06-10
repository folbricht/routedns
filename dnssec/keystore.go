package dnssec

import (
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type keystore struct {
	store map[string]*keystoreEntry
	mu    sync.RWMutex
	now   func() time.Time
}

type keystoreEntry struct {
	keys *dnskeySet
	ds   *dsSet
	mu   sync.RWMutex
}

func (item *keystoreEntry) setDNSKEY(keys *dnskeySet) {
	item.mu.Lock()
	defer item.mu.Unlock()
	item.keys = keys
}

type dnskeySet struct {
	expiresAt time.Time
	zsk       []*dns.DNSKEY
	ksk       []*dns.DNSKEY
}

type dsSet struct {
	expiresAt time.Time
	records   []*dns.DS
}

func newKeystore(now func() time.Time) *keystore {
	return &keystore{
		store: make(map[string]*keystoreEntry),
		now:   now,
	}
}

func (s *keystore) addDS(name string, dss ...*dns.DS) {
	item := s.getItem(name)
	item.mu.Lock()
	defer item.mu.Unlock()

	// Merge with any existing DS records rather than replacing them, so that
	// multiple trust anchors for the same owner (e.g. the root KSK-2017 and
	// KSK-2024) all remain usable. Replacing would leave only the last anchor,
	// and validation would fail whenever a zone's DNSKEY RRset is signed by a
	// key matching one of the dropped anchors.
	records := make([]*dns.DS, 0, len(dss))
	if item.ds != nil {
		records = append(records, item.ds.records...)
	}
	records = append(records, dss...)

	var ttl uint32 = math.MaxUint32
	for _, ds := range records {
		if ds.Hdr.Ttl < ttl {
			ttl = ds.Hdr.Ttl
		}
	}
	item.ds = &dsSet{
		expiresAt: s.now().Add(time.Duration(ttl) * time.Second),
		records:   records,
	}
}

func (s *keystore) addDNSKEY(name string, keys []*dns.DNSKEY) {
	var (
		ttl uint32 = math.MaxUint32
		zsk []*dns.DNSKEY
		ksk []*dns.DNSKEY
	)
	for _, key := range keys {
		if key.Hdr.Ttl < ttl {
			ttl = key.Hdr.Ttl
		}
		switch key.Flags {
		case 257:
			ksk = append(ksk, key)
		case 256:
			zsk = append(zsk, key)
		}
	}
	keyset := &dnskeySet{
		expiresAt: s.now().Add(time.Duration(ttl) * time.Second),
		zsk:    zsk,
		ksk:    ksk,
	}
	item := s.getItem(name)
	item.setDNSKEY(keyset)
}

func (s *keystore) getDNSKEY(name string) (zsk, ksk []*dns.DNSKEY) {
	mk := dns.CanonicalName(name)
	s.mu.RLock()
	item, ok := s.store[mk]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	item.mu.RLock()
	defer item.mu.RUnlock()
	if item.keys == nil || s.now().After(item.keys.expiresAt) {
		return nil, nil
	}
	return item.keys.zsk, item.keys.ksk
}

func (s *keystore) getDS(name string) []*dns.DS {
	mk := dns.CanonicalName(name)
	s.mu.RLock()
	item, ok := s.store[mk]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	item.mu.RLock()
	defer item.mu.RUnlock()
	if item.ds == nil || s.now().After(item.ds.expiresAt) {
		return nil
	}
	return item.ds.records
}

// Returns an item for a domain from the keystore. The item
// is created if none exist yet.
func (s *keystore) getItem(name string) *keystoreEntry {
	mk := dns.CanonicalName(name)
	s.mu.RLock()
	item, ok := s.store[mk]
	s.mu.RUnlock()
	if ok {
		return item
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the write lock: another goroutine may have created the
	// entry between releasing the read lock above and acquiring the write lock.
	// Without this, two callers could each insert a fresh entry, the second
	// overwriting the first, and any DS/DNSKEY written to the orphaned entry
	// would be silently lost.
	if item, ok := s.store[mk]; ok {
		return item
	}
	item = new(keystoreEntry)
	s.store[mk] = item
	return item
}
