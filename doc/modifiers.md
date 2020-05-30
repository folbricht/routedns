# Query and Response modifiers

## Cache

A cache will store the responses to queries in memory and respond to further identical queries with the same response. To detemine how long an item is kept in memory, the cache uses the lowest TTL of the RRs in the response. Responses served from the cache have their TTL updated according to the time it spent in memory.

### Configuration

Caches are instantiated with `type = "cache"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `cache-size` - Max number of responses to cache. Defaults to 0 which means no limit. Optional
- `cache-negative-ttl` - TTL (in seconds) to apply to responses without a SOA. Default: 60. Optional

### Examples

Simple cache without size-limit:

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]
```

Cache that only stores up to 1000 records in memory and keeps negative responses for 1h.

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]
cache-size = 1000
cache-negative-ttl = 3600
```

Example config files: [cache.toml](../cmd/routedns/example-config/cache.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml)
