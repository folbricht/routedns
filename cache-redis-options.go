package rdns

import "time"

// RedisBackendOptions holds the connection settings for the Redis cache
// backend. The fields mirror those of redis.Options so that callers don't
// need to import the Redis client, which is what allows the backend itself
// to be left out of a build with the "noredis" tag. This file is built
// either way, so the config layer in cmd/routedns compiles unchanged.
type RedisBackendOptions struct {
	Network         string // Network type, "tcp" or "unix"
	Address         string // Address of the Redis server
	Username        string
	Password        string
	DB              int    // Database to select after connecting
	KeyPrefix       string // Prefix for every cache entry
	MaxRetries      int    // Retries before giving up. -1 disables retries.
	MinRetryBackoff time.Duration
	MaxRetryBackoff time.Duration
	SyncSet         bool // When true, perform Redis SET synchronously. Default is false (async writes).
}
