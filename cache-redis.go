package rdns

import (
	"context"
	"encoding/json"
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
	key := redisKeyFromQuery(query)
	value, err := json.Marshal(item)
	if err != nil {
		Log.WithError(err).Error("failed to marshal cache record")
		return
	}
	fmt.Println(string(value))
	if err := b.client.Set(ctx, key, value, time.Until(item.Expiry)).Err(); err != nil {
		Log.WithError(err).Error("failed to write to redis")
	}
}

func (b *redisBackend) Lookup(q *dns.Msg) (*dns.Msg, bool, bool) {
	// TODO
	return nil, false, false
}

func (b *redisBackend) Flush() {
	// TODO
}

func (b *redisBackend) Size() int {
	// TODO
	return 0
}

func (b *redisBackend) Close() error {
	return b.client.Close()
}

// Build a key string to be used in redis.
func redisKeyFromQuery(q *dns.Msg) string {
	var b strings.Builder
	b.WriteString(q.Question[0].Name)
	b.WriteByte(':')
	b.WriteString(dns.Class(q.Question[0].Qclass).String())
	b.WriteByte(':')
	b.WriteString(dns.Type(q.Question[0].Qtype).String())
	b.WriteByte(':')

	edns0 := q.IsEdns0()
	if edns0 != nil {
		// See if we have a subnet option
		for _, opt := range edns0.Option {
			if subnet, ok := opt.(*dns.EDNS0_SUBNET); ok {
				b.WriteString(subnet.Address.String())
			}
		}
	}
	return b.String()
}
