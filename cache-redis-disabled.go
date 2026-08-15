//go:build noredis

package rdns

import "errors"

// NewRedisBackend replaces the real backend in builds made with the "noredis"
// tag, which leave out the Redis client. A configuration asking for the redis
// cache backend fails at startup rather than silently falling back to memory.
func NewRedisBackend(opt RedisBackendOptions) (CacheBackend, error) {
	return nil, errors.New("this build does not support the redis cache backend")
}
