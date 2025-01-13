package rdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

type redisBackend struct {
	client *redis.Client
	opt    RedisBackendOptions
}

type RedisBackendOptions struct {
	RedisOptions redis.Options
	KeyPrefix    string
}

var _ CacheBackend = (*redisBackend)(nil)

func NewRedisBackend(opt RedisBackendOptions) *redisBackend {
	b := &redisBackend{
		client: redis.NewClient(&opt.RedisOptions),
		opt:    opt,
	}
	return b
}

func (b *redisBackend) Store(query *dns.Msg, item *cacheAnswer) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	key := b.keyFromQuery(query)
	value, err := json.Marshal(item)
	if err != nil {
		Log.Error("failed to marshal cache record", "error", err)
		return
	}
	if err := b.client.Set(ctx, key, value, time.Until(item.Expiry)).Err(); err != nil {
		Log.Error("failed to write to redis", "error", err)
	}
}

func (b *redisBackend) Lookup(q *dns.Msg) (*dns.Msg, bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	key := b.keyFromQuery(q)
	value, err := b.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) { // Return a cache-miss if there's no such key
			return nil, false, false
		}
		Log.Error("failed to read from redis", "error", err)
		return nil, false, false
	}
	var a *cacheAnswer
	if err := json.Unmarshal([]byte(value), &a); err != nil {
		Log.Error("failed to unmarshal cache record from redis", "error", err)
		return nil, false, false
	}

	answer := a.Msg
	prefetchEligible := a.PrefetchEligible
	answer.Id = q.Id

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
	key.WriteString(q.Question[0].Name)
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
