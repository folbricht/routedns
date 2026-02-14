package dnssec

import (
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type keystore struct {
	store map[string]*keystoreItem
	mu    sync.RWMutex
	now   func() time.Time
}

type keystoreItem struct {
	keys *dnskeyset
	ds   *dsset
	mu   sync.RWMutex
}

func (item *keystoreItem) setDS(ds *dsset) {
	item.mu.Lock()
	defer item.mu.Unlock()
	item.ds = ds
}

func (item *keystoreItem) setDNSKEY(keys *dnskeyset) {
	item.mu.Lock()
	defer item.mu.Unlock()
	item.keys = keys
}

type dnskeyset struct {
	expiry time.Time
	zsk    []*dns.DNSKEY
	ksk    []*dns.DNSKEY
}

type dsset struct {
	expiry time.Time
	ds     []*dns.DS
}

func newKeystore(now func() time.Time) *keystore {
	return &keystore{
		store: make(map[string]*keystoreItem),
		now:   now,
	}
}

func (s *keystore) addDS(name string, dss ...*dns.DS) {
	var ttl uint32 = math.MaxUint32
	for _, ds := range dss {
		if ds.Hdr.Ttl < ttl {
			ttl = ds.Hdr.Ttl
		}
	}
	dsset := &dsset{
		expiry: s.now().Add(time.Duration(ttl) * time.Second),
		ds:     dss,
	}
	item := s.getItem(name)
	item.setDS(dsset)
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
	keyset := &dnskeyset{
		expiry: s.now().Add(time.Duration(ttl) * time.Second),
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
	if item.keys == nil || s.now().After(item.keys.expiry) {
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
	if item.ds == nil || s.now().After(item.ds.expiry) {
		return nil
	}
	return item.ds.ds
}

// Returns an item for a domain from the keystore. The item
// is created if none exist yet.
func (s *keystore) getItem(name string) *keystoreItem {
	mk := dns.CanonicalName(name)
	s.mu.RLock()
	item, ok := s.store[mk]
	s.mu.RUnlock()
	if ok {
		return item
	}
	item = new(keystoreItem)
	s.mu.Lock()
	s.store[mk] = item
	s.mu.Unlock()
	return item
}
