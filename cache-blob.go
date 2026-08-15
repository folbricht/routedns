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
// The key fields are contiguous so a lookup can compare them as one span, and
// so an on-disk format can hash the same bytes.
type cacheBlob []byte

const (
	blobVersion = 1

	blobOffMetaFlags = 1
	blobOffTimestamp = 2
	blobOffExpiry    = 10
	blobOffKeyFlags  = 18
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
	wire, err := a.Msg.PackBuffer((*bufPtr)[:cap(*bufPtr)])
	if err != nil {
		putPackBuf(bufPtr)
		return nil, err
	}
	// If packing outgrew the pooled buffer, keep the larger one so the pool
	// adapts to the workload.
	if cap(wire) > cap(*bufPtr) {
		*bufPtr = wire
	}
	blob, err := newCacheBlobFromWire(key, unixNano(a.Timestamp), unixNano(a.Expiry), a.PrefetchEligible, wire)
	putPackBuf(bufPtr)
	return blob, err
}

// newCacheBlobFromWire builds the stored form in one exact-size allocation
// from a message that is already packed.
func newCacheBlobFromWire(key lruKey, timestamp, expiry int64, prefetchEligible bool, wire []byte) (cacheBlob, error) {
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
	blob[0] = blobVersion
	if prefetchEligible {
		blob[blobOffMetaFlags] |= blobMetaPrefetchEligible
	}
	binary.BigEndian.PutUint64(blob[blobOffTimestamp:], uint64(timestamp))
	binary.BigEndian.PutUint64(blob[blobOffExpiry:], uint64(expiry))
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

func (b cacheBlob) prefetchEligible() bool {
	return b[blobOffMetaFlags]&blobMetaPrefetchEligible != 0
}

func (b cacheBlob) netLen() int {
	return int(binary.BigEndian.Uint16(b[blobOffNetLen:]))
}

func (b cacheBlob) nameLen() int {
	return int(binary.BigEndian.Uint16(b[blobOffNameLen:]))
}

// message returns the packed message, which aliases the blob.
func (b cacheBlob) message() []byte {
	return b[blobHdrLen+b.netLen()+b.nameLen():]
}

// matchesKey reports whether the blob was stored under key. Comparing a byte
// slice against a string this way doesn't allocate.
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
