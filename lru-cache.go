package rdns

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
)

type lruCache struct {
	maxItems   int
	items      map[lruKey]*cacheItem
	head, tail *cacheItem
}

type cacheItem struct {
	Key        lruKey
	Answer     *cacheAnswer
	prev, next *cacheItem
}

type lruKey struct {
	Question dns.Question
	Net      string
	Do       bool
	CD       bool  // RFC 4035 §4.7 / RFC 6840 §5.9: CD=1 responses are unvalidated and must not be served to CD=0 clients
	ECSMask  uint8 // ECS source prefix length; responses with differing scope must not collide
}

type cacheAnswer struct {
	Timestamp        time.Time // Time the record was cached. Needed to adjust TTL
	Expiry           time.Time // Time the record expires and should be removed
	PrefetchEligible bool      // The cache can prefetch this record
	Msg              *dns.Msg
}

// Reports whether the record is still valid at time now. The single
// definition of the expiry rule, used by lookups, GC, and both sides of
// cache-file persistence.
func (c *cacheAnswer) live(now time.Time) bool {
	return !now.After(c.Expiry)
}

// The custom JSON marshaling defines the on-disk format of the cache file
// (MemoryBackendOptions.Filename), packing the message to wire format.
//
// serialize() doesn't call this; it writes the same JSON via an append
// encoder. This stays as the format definition alongside UnmarshalJSON, and
// as the oracle TestLRUSerializeMatchesEncodingJSON checks that encoder against.
func (c cacheAnswer) MarshalJSON() ([]byte, error) {
	msg, err := c.Msg.Pack()
	if err != nil {
		return nil, err
	}
	type alias cacheAnswer
	record := struct {
		alias
		Msg []byte
	}{
		alias: alias(c),
		Msg:   msg,
	}
	return json.Marshal(record)
}

func (c *cacheAnswer) UnmarshalJSON(data []byte) error {
	type alias cacheAnswer
	aux := struct {
		*alias
		Msg []byte
	}{
		alias: (*alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	c.Msg = new(dns.Msg)
	return c.Msg.Unpack(aux.Msg)
}

func newLRUCache(capacity int) *lruCache {
	head := new(cacheItem)
	tail := new(cacheItem)
	head.next = tail
	tail.prev = head

	return &lruCache{
		maxItems: capacity,
		items:    make(map[lruKey]*cacheItem),
		head:     head,
		tail:     tail,
	}
}

func (c *lruCache) add(query *dns.Msg, answer *cacheAnswer) {
	key := lruKeyFromQuery(query)
	c.addKey(key, answer)
}

func (c *lruCache) addKey(key lruKey, answer *cacheAnswer) {
	item := c.touch(key)
	if item != nil {
		// Update the item, it's already at the top of the list
		// so we can just change the value
		item.Answer = answer
		return
	}
	// Add new item to the top of the linked list
	item = &cacheItem{
		Key:    key,
		Answer: answer,
		next:   c.head.next,
		prev:   c.head,
	}
	c.head.next.prev = item
	c.head.next = item
	c.items[key] = item
	c.resize()
}

// Loads a cache item and puts it to the top of the queue (most recent).
func (c *lruCache) touch(key lruKey) *cacheItem {
	item := c.items[key]
	if item == nil {
		return nil
	}
	// move the item to the top of the linked list
	item.prev.next = item.next
	item.next.prev = item.prev
	item.next = c.head.next
	item.prev = c.head
	c.head.next.prev = item
	c.head.next = item
	return item
}

func (c *lruCache) delete(q *dns.Msg) {
	key := lruKeyFromQuery(q)
	item := c.items[key]
	if item == nil {
		return
	}
	item.prev.next = item.next
	item.next.prev = item.prev
	delete(c.items, key)
}

func (c *lruCache) get(query *dns.Msg) *cacheAnswer {
	key := lruKeyFromQuery(query)
	item := c.touch(key)
	if item != nil {
		return item.Answer
	}
	return nil
}

// Shrink the cache down to the maximum number of items.
func (c *lruCache) resize() {
	if c.maxItems <= 0 { // no size limit
		return
	}
	drop := len(c.items) - c.maxItems
	for range drop {
		item := c.tail.prev
		item.prev.next = c.tail
		c.tail.prev = item.prev
		delete(c.items, item.Key)
	}
}

// Clear the cache.
func (c *lruCache) reset() {
	head := new(cacheItem)
	tail := new(cacheItem)
	head.next = tail
	tail.prev = head

	c.head = head
	c.tail = tail
	c.items = make(map[lruKey]*cacheItem)
}

// Iterate over the cached answers and call the provided function. If it
// returns true, the item is deleted from the cache.
func (c *lruCache) deleteFunc(f func(*cacheAnswer) bool) {
	item := c.head.next
	for item != c.tail {
		if f(item.Answer) {
			item.prev.next = item.next
			item.next.prev = item.prev
			delete(c.items, item.Key)
		}
		item = item.next
	}
}

func (c *lruCache) size() int {
	return len(c.items)
}

// Writes the cache as newline-delimited JSON, oldest item first, so that
// deserialize() re-inserts them in the same order and preserves the LRU
// ordering. Expired items are skipped; they'd be dropped on load anyway.
//
// Records are encoded by appending to a reused buffer rather than via
// json.Encoder, which would reflect over every record and re-parse the
// output of cacheAnswer.MarshalJSON to compact it.
//
// Records that can't be packed are dropped rather than failing the whole
// save, and summarised in a single log line so a systematic problem doesn't
// turn into one line per record on every save-interval. Returns how many
// were dropped, for the caller to surface as a metric.
func (c *lruCache) serialize(w io.Writer, log *slog.Logger) (skipped int, err error) {
	now := time.Now()
	var (
		buf      []byte // reused line buffer
		wire     []byte // reused message wire-format buffer
		firstErr error
		firstQ   string
	)
	for item := c.tail.prev; item != c.head; item = item.prev {
		if item.Answer == nil || !item.Answer.live(now) {
			continue
		}
		// PackBuffer only reuses the buffer if its *length* is sufficient, and
		// it returns a length-truncated slice. Pass the full capacity back in,
		// then keep whichever buffer is larger, or nothing is ever reused.
		packed, err := item.Answer.Msg.PackBuffer(wire[:cap(wire)])
		if err != nil {
			// A record that can't be packed can't be restored either.
			skipped++
			if firstErr == nil {
				// Report the first failure, not the last: for a systematic
				// problem the first is the actionable one.
				firstErr, firstQ = err, item.Key.Question.Name
			}
			continue
		}
		if cap(packed) > cap(wire) {
			wire = packed
		}
		// packed must be fully consumed before the next PackBuffer call, which
		// reuses (and so overwrites) the same array. appendCacheItemJSON copies
		// it into buf, and w is expected to copy rather than retain what it's
		// handed -- passing packed to a writer that keeps the slice would
		// corrupt earlier records.
		buf = appendCacheItemJSON(buf[:0], item, packed)
		if _, err := w.Write(buf); err != nil {
			return skipped, err
		}
	}
	if skipped > 0 {
		log.Warn("failed to pack cached messages, records not persisted",
			"skipped", skipped, "first_qname", firstQ, "first_error", firstErr)
	}
	return skipped, nil
}

// Appends one cache item to buf as a single JSON line, matching the layout
// produced by encoding/json for cacheItem/cacheAnswer.
//
// The field list below must track lruKey, cacheAnswer, and dns.Question --
// the last owned by miekg/dns, so a dependency bump can also break this.
// TestLRUSerializeMatchesEncodingJSON compares against encoding/json at test
// time and fails if any of the three gains or reorders a field.
func appendCacheItemJSON(buf []byte, item *cacheItem, wire []byte) []byte {
	k, a := item.Key, item.Answer

	buf = append(buf, `{"Key":{"Question":{"Name":`...)
	buf = appendJSONString(buf, k.Question.Name)
	buf = append(buf, `,"Qtype":`...)
	buf = strconv.AppendUint(buf, uint64(k.Question.Qtype), 10)
	buf = append(buf, `,"Qclass":`...)
	buf = strconv.AppendUint(buf, uint64(k.Question.Qclass), 10)
	buf = append(buf, `},"Net":`...)
	buf = appendJSONString(buf, k.Net)
	buf = append(buf, `,"Do":`...)
	buf = strconv.AppendBool(buf, k.Do)
	buf = append(buf, `,"CD":`...)
	buf = strconv.AppendBool(buf, k.CD)
	buf = append(buf, `,"ECSMask":`...)
	buf = strconv.AppendUint(buf, uint64(k.ECSMask), 10)

	buf = append(buf, `},"Answer":{"Timestamp":`...)
	buf = appendJSONTime(buf, a.Timestamp)
	buf = append(buf, `,"Expiry":`...)
	buf = appendJSONTime(buf, a.Expiry)
	buf = append(buf, `,"PrefetchEligible":`...)
	buf = strconv.AppendBool(buf, a.PrefetchEligible)
	buf = append(buf, `,"Msg":"`...)
	buf = base64.StdEncoding.AppendEncode(buf, wire)
	buf = append(buf, "\"}}\n"...)
	return buf
}

func appendJSONTime(buf []byte, t time.Time) []byte {
	buf = append(buf, '"')
	buf = t.AppendFormat(buf, time.RFC3339Nano)
	return append(buf, '"')
}

// Appends s as a quoted JSON string. Domain names and IP addresses are
// almost always plain ASCII, so the common path is a straight copy; anything
// needing escaping falls back to encoding/json.
//
// '<', '>' and '&' must take the fallback too: encoding/json escapes them to
// their \u00xx form by default, and they are valid bytes inside a DNS label,
// so copying them verbatim would diverge from the previous output.
func appendJSONString(buf []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == '"' || c == '\\' || c >= utf8.RuneSelf ||
			c == '<' || c == '>' || c == '&' {
			b, err := json.Marshal(s)
			if err != nil { // cannot happen for a string
				return append(buf, `""`...)
			}
			return append(buf, b...)
		}
	}
	buf = append(buf, '"')
	buf = append(buf, s...)
	return append(buf, '"')
}

func (c *lruCache) deserialize(r io.Reader) error {
	now := time.Now()
	dec := json.NewDecoder(r)
	for dec.More() {
		item := new(cacheItem)
		if err := dec.Decode(item); err != nil {
			return err
		}
		// Skip bad (or incompatible) records
		if item.Key.Question.Name == "" || item.Answer == nil {
			continue
		}
		// Skip records that expired while the file sat on disk; until the
		// next lookup or GC run they'd occupy capacity live records could use.
		// Files written by older versions aren't filtered on the write side.
		if !item.Answer.live(now) {
			continue
		}
		c.addKey(item.Key, item.Answer)
	}
	return nil
}

func lruKeyFromQuery(q *dns.Msg) lruKey {
	question := q.Question[0]
	// disregard case of the question name when storing
	question.Name = strings.ToLower(question.Name)
	key := lruKey{Question: question, CD: q.CheckingDisabled}

	edns0 := q.IsEdns0()
	if edns0 != nil {
		key.Do = edns0.Do()
		// See if we have a subnet option
		for _, opt := range edns0.Option {
			if subnet, ok := opt.(*dns.EDNS0_SUBNET); ok {
				key.Net = subnet.Address.String()
				key.ECSMask = subnet.SourceNetmask
			}
		}
	}
	return key
}
