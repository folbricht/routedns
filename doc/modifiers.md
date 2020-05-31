# Query and Response modifiers

## Cache

A cache will store the responses to queries in memory and respond to further identical queries with the same response. To detemine how long an item is kept in memory, the cache uses the lowest TTL of the RRs in the response. Responses served from the cache have their TTL updated according to the time it spent in memory.

Caches can be combined with a [TTL Modifier](#TTLmodifier) to avoid too many cache-misses due to excessively low TTL values.

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

## TTL modifier

A TTL modifier is used to adjust the time-to-live (TTL) of DNS responses. This is used to avoid frequently making the same queries to upstream because many responses have a value that is unreasonably low as outlined in this [blog](https://blog.apnic.net/2019/11/12/stop-using-ridiculously-low-dns-ttls). It's also possible to restrict very high TTL values that might be used in DNS poining attacks.

The limits are applied to all RRs in a response.

### Configuration

Caches are instantiated with `type = "ttl-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `ttl-min` - TTL minimum (in seconds) to apply to responses
- `ttl-max` - TTL minimum (in seconds) to apply to responses

### Examples

TTL modifier that returns responses with TTL of between 1h and one day:

```toml
[groups.cloudflare-updated-ttl]
type = "ttl-modifier"
resolvers = ["cloudflare-dot"]
ttl-min = 3600
ttl-max = 86400
```

Example config files: [ttl-modifier.toml](../cmd/routedns/example-config/ttl-modifier.toml)
