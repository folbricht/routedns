package rdns

import (
	"context"
	"encoding/binary"
	"errors"
	"expvar"
	"fmt"
	"strconv"
	"strings"
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

// The record format this backend wrote before it shared a layout with the
// memory backend. Still read, no longer written; see decodeRecord.
const (
	binaryFormatVersion = 1
	headerSize          = 10
	flagPrefetchBit     = 1 << 0
)

// decodeRecord decodes a stored record, whichever format it is in. Version 2
// is the blob layout shared with the memory backend, which this backend now
// writes. Version 1 is the format above, which it wrote until this release.
//
// Reading version 1 keeps a shared cache usable while instances are on either
// side of the upgrade. It does not have to stay: every record is stored with a
// TTL, so version 1 drains within one DNS TTL of the last instance writing it
// stopping, and reading it can go then.
func decodeRecord(b []byte) (*cacheAnswer, error) {
	if len(b) == 0 {
		return nil, errors.New("empty cache record")
	}
	switch b[0] {
	case blobVersion:
		return cacheBlob(b).cacheAnswer()
	case binaryFormatVersion:
		return decodeCacheAnswer(b)
	}
	return nil, fmt.Errorf("unsupported cache record version: %d", b[0])
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

	// The redis key already encodes the question, so the record is stored
	// under the empty key: the region costs its ten header bytes and nothing
	// would read it back. newCacheBlob returns its own allocation, so the
	// value can be handed to a background write as it is.
	value, err := newCacheBlob(lruKey{}, item)
	if err != nil {
		Log.Error("failed to encode cache record", "error", err)
		return
	}

	if b.opt.SyncSet {
		b.set(key, value, ttl)
		return
	}

	// Non-blocking semaphore acquire.
	select {
	case b.asyncWriteSem <- struct{}{}:
		go func() {
			defer func() { <-b.asyncWriteSem }()
			b.set(key, value, ttl)
		}()
	default:
		// Semaphore full, skip async store (best-effort caching)
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

	a, err := decodeRecord(valueBytes)
	if err != nil {
		Log.Error("failed to decode cache record from redis", "error", err)
		return nil, false, false
	}

	// A record that has aged out is left in place: Redis expires it on its
	// own TTL, so deleting it here would only cost a round trip.
	age := cacheAge(time.Now().UnixNano(), a.Timestamp.UnixNano())
	if !ageCachedAnswer(a.Msg, q, age) {
		return nil, false, false
	}

	return a.Msg, a.PrefetchEligible, true
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
