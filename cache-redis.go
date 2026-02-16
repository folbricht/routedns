package rdns

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
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

// Buffer pool for dns.Msg.PackBuffer to minimize allocations.
var packBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
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
func encodeCacheAnswer(item *cacheAnswer) ([]byte, error) {
	bufPtr := packBufPool.Get().(*[]byte)
	buf := *bufPtr

	defer func() {
		*bufPtr = buf[:0]
		packBufPool.Put(bufPtr)
	}()

	if cap(buf) == 0 {
		buf = make([]byte, 0, 2048)
	}

	// Pack DNS message first into the scratch buffer
	buf = buf[:cap(buf)]
	dnsWire, err := item.Msg.PackBuffer(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Keep the (potentially grown) buffer for cleanup
	buf = dnsWire

	// Allocate result with header + DNS wire bytes
	result := make([]byte, headerSize+len(dnsWire))

	// Write header
	result[0] = binaryFormatVersion

	var flags byte
	if item.PrefetchEligible {
		flags |= flagPrefetchBit
	}
	result[1] = flags

	timestamp := uint64(item.Timestamp.Unix())
	binary.BigEndian.PutUint64(result[2:10], timestamp)

	// Copy DNS wire bytes after header
	copy(result[headerSize:], dnsWire)

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

	if b.opt.SyncSet {
		b.storeSync(query, item, ttl)
	} else {
		b.storeAsync(query, item, ttl)
	}
}

func (b *redisBackend) storeSync(query *dns.Msg, item *cacheAnswer, ttl time.Duration) {
	key := b.keyFromQuery(query)
	value, err := encodeCacheAnswer(item)
	if err != nil {
		Log.Error("failed to encode cache record", "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := b.client.Set(ctx, key, value, ttl).Err(); err != nil {
		Log.Error("failed to write to redis", "error", err)
	}
}

func (b *redisBackend) storeAsync(query *dns.Msg, item *cacheAnswer, ttl time.Duration) {
	// Non-blocking semaphore acquire
	select {
	case b.asyncWriteSem <- struct{}{}:
		go func() {
			defer func() { <-b.asyncWriteSem }()
			b.storeSync(query, item, ttl)
		}()
	default:
		// Semaphore full, skip async store (best-effort caching)
		b.asyncSkipped.Add(1)
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

	// Try binary decode first, with JSON fallback for backward compatibility
	var a *cacheAnswer
	a, err = decodeCacheAnswer(valueBytes)
	if err != nil {
		// Fallback to JSON for backward compatibility with existing cached entries
		if jsonErr := json.Unmarshal(valueBytes, &a); jsonErr != nil {
			Log.Error("failed to decode cache record from redis", "binary_error", err, "json_error", jsonErr)
			return nil, false, false
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := b.client.Del(ctx, b.opt.KeyPrefix+"*").Result(); err != nil {
		Log.Error("failed to delete keys in redis", "error", err)
	}
}

func (b *redisBackend) Size() int {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
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
	var key strings.Builder
	key.WriteString(b.opt.KeyPrefix)
	key.WriteString(strings.ToLower(q.Question[0].Name))
	key.WriteByte(':')
	key.WriteString(dns.Class(q.Question[0].Qclass).String())
	key.WriteByte(':')
	key.WriteString(dns.Type(q.Question[0].Qtype).String())
	key.WriteByte(':')

	edns0 := q.IsEdns0()
	if edns0 != nil {
		key.WriteString(fmt.Sprintf("%t", edns0.Do()))
		key.WriteByte(':')
		// See if we have a subnet option
		for _, opt := range edns0.Option {
			if subnet, ok := opt.(*dns.EDNS0_SUBNET); ok {
				key.WriteString(subnet.Address.String())
			}
		}
	}
	return key.String()
}
