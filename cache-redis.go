package rdns

import (
	"context"
	"encoding/binary"
	"errors"
	"expvar"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

const (
	// asyncWriteSemCapacity limits concurrent background Redis writes.
	redisAsyncWriteSemCapacity = 256
)

type redisBackend struct {
	client        *redis.Client
	opt           RedisBackendOptions
	asyncWriteSem chan struct{}
	asyncSkipped  *expvar.Int
}

type RedisBackendOptions struct {
	RedisOptions redis.Options
	KeyPrefix    string
	SyncSet      bool // When true, perform Redis SET synchronously. Default is false (async writes).
}

var _ CacheBackend = (*redisBackend)(nil)

// Buffer pool for encoding cache records to minimize allocations.
var packBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

func putPackBuf(bufPtr *[]byte) {
	*bufPtr = (*bufPtr)[:0]
	packBufPool.Put(bufPtr)
}

const (
	binaryFormatVersion = 1
	headerSize          = 10
	flagPrefetchBit     = 1 << 0
)

// encodeCacheAnswer encodes a cacheAnswer into a compact binary format:
// - byte 0: version (1)
// - byte 1: flags (bit0: prefetchEligible)
// - bytes 2..9: timestamp (uint64 seconds from Unix epoch, big endian)
// - bytes 10..N: dns.Msg wire bytes
//
// The message is packed into buf when it fits, so the returned slice
// typically aliases buf. The caller owns buf and must not reuse it while
// the result is in use.
func encodeCacheAnswer(buf []byte, item *cacheAnswer) ([]byte, error) {
	if cap(buf) < headerSize {
		buf = make([]byte, headerSize+2048)
	}
	buf = buf[:cap(buf)]

	// Pack the DNS message directly after the header. PackBuffer packs
	// in place and only allocates a new buffer if the message doesn't fit.
	dnsWire, err := item.Msg.PackBuffer(buf[headerSize:])
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	var result []byte
	if &dnsWire[0] == &buf[headerSize] {
		// Packed in place, header and wire bytes are contiguous in buf
		result = buf[:headerSize+len(dnsWire)]
	} else {
		// The message didn't fit and PackBuffer allocated a new buffer
		result = make([]byte, headerSize+len(dnsWire))
		copy(result[headerSize:], dnsWire)
	}

	// Write header
	result[0] = binaryFormatVersion

	var flags byte
	if item.PrefetchEligible {
		flags |= flagPrefetchBit
	}
	result[1] = flags

	binary.BigEndian.PutUint64(result[2:10], uint64(item.Timestamp.Unix()))

	return result, nil
}

// decodeCacheAnswer decodes a binary-encoded cacheAnswer.
// Returns an error if the format is invalid or unsupported.
func decodeCacheAnswer(b []byte) (*cacheAnswer, error) {
	if len(b) < headerSize {
		return nil, fmt.Errorf("binary data too short: %d bytes", len(b))
	}

	// Check version
	version := b[0]
	if version != binaryFormatVersion {
		return nil, fmt.Errorf("unsupported binary format version: %d", version)
	}

	// Parse flags
	flags := b[1]
	prefetchEligible := (flags & flagPrefetchBit) != 0

	// Parse timestamp
	timestamp := int64(binary.BigEndian.Uint64(b[2:10]))

	// Unpack DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(b[headerSize:]); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	return &cacheAnswer{
		Timestamp:        time.Unix(timestamp, 0),
		PrefetchEligible: prefetchEligible,
		Msg:              msg,
	}, nil
}

func NewRedisBackend(opt RedisBackendOptions) *redisBackend {
	b := &redisBackend{
		client:        redis.NewClient(&opt.RedisOptions),
		opt:           opt,
		asyncWriteSem: make(chan struct{}, redisAsyncWriteSemCapacity),
		asyncSkipped:  getVarInt("cache", "redis", "async-skipped"),
	}
	return b
}

func (b *redisBackend) Store(query *dns.Msg, item *cacheAnswer) {
	// TTL guard: skip storing if already expired
	ttl := time.Until(item.Expiry)
	if ttl <= 0 {
		return
	}

	// Build the key and encode synchronously. The query and the message
	// belong to the caller and may be mutated once Store returns, so
	// they can't be touched from a background goroutine.
	key := b.keyFromQuery(query)

	bufPtr := packBufPool.Get().(*[]byte)
	value, err := encodeCacheAnswer(*bufPtr, item)
	if err != nil {
		putPackBuf(bufPtr)
		Log.Error("failed to encode cache record", "error", err)
		return
	}
	// If encoding outgrew the pooled buffer, keep the larger one so the
	// pool adapts to the workload
	if cap(value) > cap(*bufPtr) {
		*bufPtr = value
	}

	if b.opt.SyncSet {
		b.set(key, value, ttl)
		putPackBuf(bufPtr)
		return
	}

	// Non-blocking semaphore acquire. The value buffer is handed to the
	// goroutine and returned to the pool once the write completes.
	select {
	case b.asyncWriteSem <- struct{}{}:
		go func() {
			defer func() {
				putPackBuf(bufPtr)
				<-b.asyncWriteSem
			}()
			b.set(key, value, ttl)
		}()
	default:
		// Semaphore full, skip async store (best-effort caching)
		putPackBuf(bufPtr)
		b.asyncSkipped.Add(1)
	}
}

func (b *redisBackend) set(key string, value []byte, ttl time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := b.client.Set(ctx, key, value, ttl).Err(); err != nil {
		Log.Error("failed to write to redis", "error", err)
	}
}

func (b *redisBackend) Lookup(q *dns.Msg) (*dns.Msg, bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	key := b.keyFromQuery(q)

	// Fetch raw bytes to avoid string conversion overhead
	valueBytes, err := b.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) { // Return a cache-miss if there's no such key
			return nil, false, false
		}
		Log.Error("failed to read from redis", "error", err)
		return nil, false, false
	}

	a, err := decodeCacheAnswer(valueBytes)
	if err != nil {
		Log.Error("failed to decode cache record from redis", "error", err)
		return nil, false, false
	}

	answer := a.Msg
	prefetchEligible := a.PrefetchEligible
	answer.Id = q.Id
	answer.Question = q.Question // restore the case used in the question

	// Calculate the time the record spent in the cache. We need to
	// subtract that from the TTL of each answer record.
	age := uint32(time.Since(a.Timestamp).Seconds())

	// Go through all the answers, NS, and Extra and adjust the TTL (subtract the time
	// it's spent in the cache). If the record is too old, evict it from the cache
	// and return a cache-miss. OPT records have a TTL of 0 and are ignored.
	for _, rr := range [][]dns.RR{answer.Answer, answer.Ns, answer.Extra} {
		for _, a := range rr {
			if _, ok := a.(*dns.OPT); ok {
				continue
			}
			h := a.Header()
			if age >= h.Ttl {
				return nil, false, false
			}
			h.Ttl -= age
		}
	}

	return answer, prefetchEligible, true
}

func (b *redisBackend) Flush() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// DEL takes literal key names, not glob patterns, so iterate with
	// SCAN and delete the matches in batches.
	var cursor uint64
	for {
		keys, next, err := b.client.Scan(ctx, cursor, b.opt.KeyPrefix+"*", 1000).Result()
		if err != nil {
			Log.Error("failed to scan keys in redis", "error", err)
			return
		}
		if len(keys) > 0 {
			if err := b.client.Del(ctx, keys...).Err(); err != nil {
				Log.Error("failed to delete keys in redis", "error", err)
				return
			}
		}
		if next == 0 {
			return
		}
		cursor = next
	}
}

func (b *redisBackend) Size() int {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// Note: DBSIZE counts all keys in the database, not just those
	// matching KeyPrefix.
	size, err := b.client.DBSize(ctx).Result()
	if err != nil {
		Log.Error("failed to run dbsize command on redis", "error", err)
	}
	return int(size)
}

func (b *redisBackend) Close() error {
	return b.client.Close()
}

// Build a key string to be used in redis.
func (b *redisBackend) keyFromQuery(q *dns.Msg) string {
	question := q.Question[0]

	var key strings.Builder
	key.Grow(len(b.opt.KeyPrefix) + len(question.Name) + 32)
	key.WriteString(b.opt.KeyPrefix)
	key.WriteString(strings.ToLower(question.Name))
	key.WriteByte(':')
	key.WriteString(dns.Class(question.Qclass).String())
	key.WriteByte(':')
	key.WriteString(dns.Type(question.Qtype).String())
	key.WriteByte(':')
	// CD=1 responses are unvalidated (RFC 4035 §4.7 / RFC 6840 §5.9) and
	// must be keyed separately from CD=0 ones.
	if q.CheckingDisabled {
		key.WriteString("cd")
	}
	key.WriteByte(':')

	edns0 := q.IsEdns0()
	if edns0 != nil {
		if edns0.Do() {
			key.WriteString("true")
		} else {
			key.WriteString("false")
		}
		key.WriteByte(':')
		// See if we have a subnet option
		for _, opt := range edns0.Option {
			if subnet, ok := opt.(*dns.EDNS0_SUBNET); ok {
				key.WriteString(subnet.Address.String())
				key.WriteByte('/')
				key.WriteString(strconv.FormatUint(uint64(subnet.SourceNetmask), 10))
			}
		}
	}
	return key.String()
}
