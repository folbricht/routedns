package rdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/miekg/dns"
)

// cacheBlob is one cache entry in stored form: the key, its metadata and the
// message in wire format, in a single allocation. It holds no pointers, so the
// collector skips its contents where an unpacked dns.Msg is a tree of about a
// dozen objects it has to trace on every cycle.
//
// A blob is never modified once built. Replacing an entry allocates a new one,
// so a reader that took it under a lock can decode it after releasing the lock.
//
// Layout. Offsets are fixed so the metadata can be read without decoding the
// key or the message:
//
//	0      version
//	1      meta flags (prefetch-eligible)
//	2..9   timestamp, unix nanoseconds
//	10..17 expiry, unix nanoseconds
//	18     key flags (DO, CD)          <- key region starts
//	19..20 qtype
//	21..22 qclass
//	23     ECS source prefix length
//	24..25 length of the ECS address
//	26..27 length of the question name
//	28..   ECS address, then question name
//	       <- key region ends, packed message follows
//
// Everything the key is built from sits in one span, which keyRegion returns.
// Nothing on the query path needs that today, but it is what lets a stored
// blob be matched, or hashed, without decoding it back into an lruKey.
type cacheBlob []byte

// blobVersion is the version of the layout above. It is written into every
// blob and checked wherever one is read back from storage, so a later change
// to the layout keeps old records out of accessors that no longer match them.
//
// 0 was this layout while it lived only in memory and in the cache file, and 1
// is binaryFormatVersion, the Redis record format from before the backends
// shared a layout, a different shape in the same first byte. A record that
// either backend may read therefore starts at 2.
const blobVersion = 2

const (
	blobOffVersion   = 0
	blobOffMetaFlags = 1
	blobOffTimestamp = 2
	blobOffExpiry    = 10
	blobOffKeyFlags  = 18 // first byte of the key region
	blobOffQtype     = 19
	blobOffQclass    = 21
	blobOffECSMask   = 23
	blobOffNetLen    = 24
	blobOffNameLen   = 26
	blobHdrLen       = 28
)

const (
	blobMetaPrefetchEligible = 1 << 0

	blobKeyDo = 1 << 0
	blobKeyCD = 1 << 1
)

// newCacheBlob packs an answer's message into a pooled buffer and builds the
// stored form from it. The message is not retained.
func newCacheBlob(key lruKey, a *cacheAnswer) (cacheBlob, error) {
	if a.Msg == nil {
		return nil, errors.New("cache item has no message")
	}
	bufPtr := packBufPool.Get().(*[]byte)
	defer putPackBuf(bufPtr)

	wire, err := a.Msg.PackBuffer((*bufPtr)[:cap(*bufPtr)])
	if err != nil {
		return nil, err
	}
	adoptPackBuf(bufPtr, wire)
	return newCacheBlobFromWire(key, a, wire)
}

// newCacheBlobFromWire builds the stored form in one exact-size allocation.
// meta supplies the timestamps and flags; its Msg is ignored in favour of
// wire, which is the message already in wire format.
func newCacheBlobFromWire(key lruKey, meta *cacheAnswer, wire []byte) (cacheBlob, error) {
	// The protocol caps a name at 255 octets on the wire, but this is the
	// presentation form, where an unprintable octet escapes to \DDD and a
	// legal name can run four times that. Both lengths get a uint16, which no
	// name can outgrow; the checks are here so the encoding stays total.
	if len(key.Question.Name) > math.MaxUint16 {
		return nil, fmt.Errorf("question name too long to cache: %d bytes", len(key.Question.Name))
	}
	if len(key.Net) > math.MaxUint16 {
		return nil, fmt.Errorf("ECS address too long to cache: %d bytes", len(key.Net))
	}

	blob := make(cacheBlob, blobHdrLen+len(key.Net)+len(key.Question.Name)+len(wire))
	blob[blobOffVersion] = blobVersion
	if meta.PrefetchEligible {
		blob[blobOffMetaFlags] |= blobMetaPrefetchEligible
	}
	binary.BigEndian.PutUint64(blob[blobOffTimestamp:], uint64(unixNano(meta.Timestamp)))
	binary.BigEndian.PutUint64(blob[blobOffExpiry:], uint64(unixNano(meta.Expiry)))
	blob[blobOffKeyFlags] = keyFlags(key)
	binary.BigEndian.PutUint16(blob[blobOffQtype:], key.Question.Qtype)
	binary.BigEndian.PutUint16(blob[blobOffQclass:], key.Question.Qclass)
	blob[blobOffECSMask] = key.ECSMask
	binary.BigEndian.PutUint16(blob[blobOffNetLen:], uint16(len(key.Net)))
	binary.BigEndian.PutUint16(blob[blobOffNameLen:], uint16(len(key.Question.Name)))

	n := blobHdrLen
	n += copy(blob[n:], key.Net)
	n += copy(blob[n:], key.Question.Name)
	copy(blob[n:], wire)
	return blob, nil
}

func keyFlags(key lruKey) byte {
	var flags byte
	if key.Do {
		flags |= blobKeyDo
	}
	if key.CD {
		flags |= blobKeyCD
	}
	return flags
}

func (b cacheBlob) timestamp() int64 {
	return int64(binary.BigEndian.Uint64(b[blobOffTimestamp:]))
}

func (b cacheBlob) expiry() int64 {
	return int64(binary.BigEndian.Uint64(b[blobOffExpiry:]))
}

func (b cacheBlob) version() byte {
	return b[blobOffVersion]
}

func (b cacheBlob) prefetchEligible() bool {
	return b[blobOffMetaFlags]&blobMetaPrefetchEligible != 0
}

func (b cacheBlob) netLen() int {
	return int(binary.BigEndian.Uint16(b[blobOffNetLen:]))
}

func (b cacheBlob) nameLen() int {
	return int(binary.BigEndian.Uint16(b[blobOffNameLen:]))
}

// keyRegion returns the span that encodes the key, which is a pure function of
// the key it was stored under and independent of the metadata and message.
func (b cacheBlob) keyRegion() []byte {
	return b[blobOffKeyFlags : blobHdrLen+b.netLen()+b.nameLen()]
}

// message returns the packed message, which aliases the blob.
func (b cacheBlob) message() []byte {
	return b[blobHdrLen+b.netLen()+b.nameLen():]
}

// matchesKey reports whether the blob was stored under key. Every field of
// lruKey has to be checked here; TestBlobKeyComparisonCoversEveryField fails if
// one is dropped, since missing one serves a response stored under a different
// question. Comparing a byte slice against a string doesn't allocate.
func (b cacheBlob) matchesKey(key lruKey) bool {
	if len(b) < blobHdrLen {
		return false
	}
	netLen, nameLen := b.netLen(), b.nameLen()
	if len(b) < blobHdrLen+netLen+nameLen ||
		b[blobOffKeyFlags] != keyFlags(key) ||
		b[blobOffECSMask] != key.ECSMask ||
		netLen != len(key.Net) ||
		nameLen != len(key.Question.Name) ||
		binary.BigEndian.Uint16(b[blobOffQtype:]) != key.Question.Qtype ||
		binary.BigEndian.Uint16(b[blobOffQclass:]) != key.Question.Qclass {
		return false
	}
	return string(b[blobHdrLen:blobHdrLen+netLen]) == key.Net &&
		string(b[blobHdrLen+netLen:blobHdrLen+netLen+nameLen]) == key.Question.Name
}

// key rebuilds the key the blob was stored under. Used when writing the cache
// file, not on the query path.
func (b cacheBlob) key() lruKey {
	netLen, nameLen := b.netLen(), b.nameLen()
	return lruKey{
		Question: dns.Question{
			Name:   string(b[blobHdrLen+netLen : blobHdrLen+netLen+nameLen]),
			Qtype:  binary.BigEndian.Uint16(b[blobOffQtype:]),
			Qclass: binary.BigEndian.Uint16(b[blobOffQclass:]),
		},
		Net:     string(b[blobHdrLen : blobHdrLen+netLen]),
		Do:      b[blobOffKeyFlags]&blobKeyDo != 0,
		CD:      b[blobOffKeyFlags]&blobKeyCD != 0,
		ECSMask: b[blobOffECSMask],
	}
}

// cacheAnswer decodes a blob back into the form the cache layer works with.
// Used by the Redis backend, which hands its records to callers as a
// cacheAnswer; the memory backend serves a hit straight off the blob and needs
// none of this.
func (b cacheBlob) cacheAnswer() (*cacheAnswer, error) {
	if len(b) < blobHdrLen || blobHdrLen+b.netLen()+b.nameLen() > len(b) {
		return nil, fmt.Errorf("cache record too short: %d bytes", len(b))
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(b.message()); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}
	return &cacheAnswer{
		Timestamp:        nanoTime(b.timestamp()),
		Expiry:           nanoTime(b.expiry()),
		PrefetchEligible: b.prefetchEligible(),
		Msg:              msg,
	}, nil
}
