# Caching and Performance

Part of the [RouteDNS Configuration Guide](configuration.md).

## Cache

A cache will store the responses to queries in memory and respond to further identical queries with the same response. To determine how long an item is kept in memory, the cache uses the lowest TTL of the RRs in the response. Responses served from the cache have their TTL updated according to the time the records spent in memory. If a query has an [ECS Subnet](https://tools.ietf.org/html/rfc7871) option, the subnet address forms part of the key to support subnet-specific answers.

Caches can be combined with a [TTL Modifier](#ttl-modifier) to avoid too many cache-misses due to excessively low TTL values.

It is possible to pre-define a query name that will flush the cache if received from a client.

The content of memory caches can be persisted to and loaded from disk.

### Configuration

Caches are instantiated with `type = "cache"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `cache-size` - Max number of responses to cache. Defaults to 0 which means no limit. Deprecated, set limit in the backend instead.
- `gc-period` - How often (in seconds) expired items are swept out of the cache. Deprecated, set it in the backend instead.
- `cache-negative-ttl` - TTL (in seconds) to apply to responses without a SOA. Default: 60. Optional
- `cache-rcode-max-ttl` - Map of RCODE to max TTL (in seconds) to use for records based on the status code regardless of SOA. Response codes are given in their numerical form: 0 = NOERROR, 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ... See [rfc2929#section-2.3](https://tools.ietf.org/html/rfc2929#section-2.3) for a more complete list. For example `{1 = 60, 3 = 60}` would set a limit on how long FORMERR or NXDOMAIN responses can be cached.
- `cache-answer-shuffle` - Specifies a method for changing the order of cached A/AAAA answer records. Possible values `random` or `round-robin`. Defaults to static responses if not set.
- `cache-harden-below-nxdomain` - Return NXDOMAIN for domain queries if the parent domain has a cached NXDOMAIN. See [RFC8020](https://tools.ietf.org/html/rfc8020).
- `cache-flush-query` - A query name (FQDN with trailing `.`) that if received from a client will trigger a cache flush (reset). Inactive if not set. Simple way to support flushing the cache by sending a pre-defined query name of any type. If successful, the response will be empty. The query will not be forwarded upstream by the cache.
- `cache-prefetch-trigger`- If a query is received for a record with less than `cache-prefetch-trigger` TTL left, the cache will send another, independent query to upstream with the goal of automatically refreshing the record in the cache with the response.
- `cache-prefetch-eligible` - Only records with at least `prefetch-eligible` seconds TTL are eligible to be prefetched.
- `backend` - Define what kind of storage is used for the cache. Contains multiple keys depending on type that can configure the behavior. Defaults to `memory` backend if not configured.

Backends:

**Memory backend**

The memory backend will keep all cache items in memory. It can be configured to write the content of the cache to disk on shutdown. Memory backend config has the following options:

- `type="memory"`
- `size` - Max number of responses to cache. Defaults to 0 which means no limit.
- `gc-period` - How often (in seconds) expired items are swept out of the cache. Defaults to 60. Optional.
- `filename` - File to use for persistent storage to disk. The cache will be initialized with the content from the file and it'll write the content to the same file on shutdown. Defaults to no persistence. The file is written by creating a temporary file in the same directory and renaming it into place, so the directory has to be writable, and a symlink at this path is replaced by a regular file rather than being written through. Point the option at the real location if the data needs to live elsewhere, for example on a tmpfs. A new file is created with mode `0600`, since it records what has been looked up; an existing file keeps whatever mode it already has. When running under the systemd unit shipped with the packages, use a path under `/var/cache/routedns`; see [Writable Paths](overview.md#writable-paths).
- `save-interval` - Interval (in seconds) to save the cache to file. Optional. If not set, the file is written only on shutdown.
- `file-format` - Format of the cache file, `json` (default) or `raw`. The raw format stores each entry the way the cache holds it in memory, which makes the file smaller and much faster to write and read; a 20,000-entry cache writes in a twentieth of the time and loads in a sixth. Reading detects the format from the file itself rather than from this option, so switching either way keeps an existing cache. Note that a cache file written in the raw format cannot be read by a version of RouteDNS that predates it; it is ignored and the cache starts empty.

**Redis backend**

The `redis` backend stores cached items in a Redis database. This allows multiple instances of routedns to share a common cache backend. The following options are supported:

- `type="redis"`
- `redis-network` - The network type, either `tcp` or `unix`. Defaults to `tcp`.
- `redis-address` - Address of redis database, host:port
- `redis-username` - Redis username
- `redis-password` - Redis password
- `redis-db` - Redis database to be selected
- `redis-key-prefix` - Prefixes the key of every record with this string. This can be used to share a database with other clients and avoid key conflicts.
- `redis-max-retries` - Maximum number of retries before giving up. Default is 3 retries; -1 (not 0) disables retries.
- `redis-min-retry-backoff` - Minimum back-off between each retry in milliseconds. Default is 8 milliseconds; -1 disables back-off.
- `redis-max-retry-backoff` - Maximum back-off between each retry in milliseconds. Default is 512 milliseconds; -1 disables back-off.
- `redis-sync-set` - When true, performs Redis SET operations synchronously. Default is false (async writes), meaning the response is returned immediately while the cache entry is written in the background. Note: With async mode, there is a brief window where a second identical query may also result in a miss until the background write completes.

### Examples

Simple cache without size-limit:

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]
backend = {type = "memory"}
```

Cache that only stores up to 1000 records in memory and keeps negative responses for 1h. Responses are randomized for cached responses.

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]
cache-negative-ttl = 3600
cache-answer-shuffle = "random"
backend = {type = "memory", size = 1000}
```

Cache that is flushed if a query for `flush.cache.` is received. Also persists the cache to disk.

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]
cache-flush-query = "flush.cache."
backend = {type = "memory", filename = "/var/cache/routedns/cache.json"}
```

Cache that uses Redis as backend.

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]
cache-flush-query = "flush.cache."
backend = {type = "redis", redis-address = "127.0.0.1:6379", redis-key-prefix = "routedns-"}
```

Example config files: [cache.toml](../cmd/routedns/example-config/cache.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml), [cache-flush.toml](../cmd/routedns/example-config/cache-flush.toml), [cache-with-prefetch.toml](../cmd/routedns/example-config/cache-with-prefetch.toml), [cache-rcode.toml](../cmd/routedns/example-config/cache-rcode.toml), [cache-redis.toml](../cmd/routedns/example-config/cache-redis.toml)

## Prefetch

While [Cache](#cache) has built-in prefetch capabilities, the dedicated `prefetch` group may be more appropriate for some use cases. It tracks the number of queries made within a time window and actively prefetches frequently requested records. While it actively sends queries in order to refresh a cache, it does not cache responses itself and relies on a cache upstream from it.

On multi-core systems the internal tracking caches are automatically sharded (based on `GOMAXPROCS`) to reduce lock contention under concurrent query load. This is an internal optimization only; it does not change behavior or measurably affect end-to-end query latency.

### Configuration

Prefetch groups are instantiated with `type = "prefetch"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `prefetch-window` - Minimum time between queries to remain eligible for prefetching. Supports time units `s`, `m`, and `h`. Default: 1h.
- `prefetch-threshold` - Minimum number of queries required for a name to enable prefetch. Default: 5.
- `prefetch-cache-size` - Maximum number of queries to track for prefetch. Values that are too large can cause memory issues. Prefetch is disabled if 0. Default: `prefetch-max-items * 3`.
- `prefetch-max-items` - Maximum number of items to prefetch. Values that are too large can cause memory issues. Prefetch is disabled if 0 or not set.

### Examples

Simple cache without size-limit:

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]

[groups.cloudflare-prefetch]
type = "prefetch"
resolvers = ["cloudflare-cached"]
prefetch-window = "15m"
prefetch-threshold = 3
prefetch-cache-size = 150
prefetch-max-items = 50
```

Example config files: [prefetch.toml](../cmd/routedns/example-config/prefetch.toml)

## TTL modifier

A TTL modifier is used to adjust the time-to-live (TTL) of DNS responses. This is used to avoid frequently making the same queries to upstream because many responses have a value that is unreasonably low as outlined in this [blog](https://blog.apnic.net/2019/11/12/stop-using-ridiculously-low-dns-ttls). It's also possible to restrict very high TTL values that might be used in DNS poisoning attacks.

The limits are applied to all RRs in a response.

### Configuration

TTL modifiers are instantiated with `type = "ttl-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `ttl-select` - Optional TTL selection function. Possible values "lowest", "highest", "average", "first", "last".
  - `lowest` - Lowest TTL of all response records.
  - `highest` - Highest TTL of all response records.
  - `average` - Average TTL of all response records.
  - `first` - First TTL.
  - `last` - Last TTL.
  - `random` - Random TTL between `ttl-min` and `ttl-max`. Note that not setting `ttl-max` will result in very high TTL values.
- `ttl-min` - TTL minimum (in seconds) to apply to responses.
- `ttl-max` - TTL maximum (in seconds) to apply to responses.

`ttl-min` and `ttl-max` are optional, but if configured define a floor/ceiling regardless of what `ttl-select` function is given.

### Examples

TTL modifier that returns responses with TTL of between 1h and one day:

```toml
[groups.cloudflare-updated-ttl]
type = "ttl-modifier"
resolvers = ["cloudflare-dot"]
ttl-min = 3600
ttl-max = 86400
```

TTL modifier returning the average TTL of all records, with a max of 1 day.

```toml
[groups.cloudflare-updated-ttl]
type = "ttl-modifier"
resolvers = ["cloudflare-dot"]
ttl-select = "average"
ttl-max = 86400
```

Example config files: [ttl-modifier.toml](../cmd/routedns/example-config/ttl-modifier.toml), [ttl-modifier-average.toml](../cmd/routedns/example-config/ttl-modifier-average.toml)

## Fastest TCP Probe

The `fastest-tcp` element will first perform a lookup, then send TCP probes to all A or AAAA records in the response. It can then either return just the A/AAAA record for the fastest response, or all A/AAAA sorted by response time (fastest first). Since probing multiple servers can be slow, it is typically used behind a [cache](#cache) to avoid making too many probes repeatedly. Each instance can only probe one port and if different ports are to be probed depending on the query name, a router should be used in front of it as well.

### Configuration

A Fastest TCP Probe element is instantiated with `type = "fastest-tcp"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `port` - TCP port number to probe. Default: `443`.
- `wait-all` - Instead of just returning the fastest response, wait for all probes and return them sorted by response time (fastest first). This will generally be slower as the slowest TCP probe determines the query response time. Default: `false`
- `success-ttl-min` - Minimum TTL of successful probes (in seconds). Default: 0. Similar to the `ttl-min` option of [TTL Modifier](#ttl-modifier). Typically used to cache the response for longer given how resource-intensive and slow probing can be.

### Examples

TCP probe for the HTTPS port. Successful probes are cached for 30min.

```toml
[groups.fastest-cached]
type = "cache"
resolvers = ["tcp-probe"]

[groups.tcp-probe]
type = "fastest-tcp"
port = 443
success-ttl-min = 1800
resolvers = ["cloudflare-dot"]
```

Example config files: [fastest-tcp.toml](../cmd/routedns/example-config/fastest-tcp.toml)

## Retrying Truncated Responses

The `truncated-retry` element will first perform a lookup using its primary resolver. If the response from the primary is truncated, the same query is retried with the secondary `retry-resolver`. This element is only useful if the primary resolver uses either plain UDP or DTLS as those apply limits to the size of the response. In addition, it is typically used behind a [cache](#cache) which can then store the full response and respond faster to clients which too may have to retry the query if using a UDP or DTLS listener.

### Configuration

To support switching to streaming resolvers on truncation, add an element with `type = "truncate-retry"` in the groups section of the configuration, right before the resolver.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `retry-resolver` - Must be referencing another resolver, typically using a stream-protocol such as TCP, DoH, or DoT.

### Examples

TCP probe for the HTTPS port. Successful probes are cached for 30min.

```toml
# Primary resolver (UDP)
[resolvers.cloudflare-udp]
address = "1.1.1.1:53"
protocol = "udp"
edns0-udp-size = 1232

# TCP Fallback resolver if UDP responses are truncated
[resolvers.cloudflare-tcp]
address = "1.1.1.1:53"
protocol = "tcp"

# Try UDP first, if truncated use the alternative (TCP)
[groups.retry]
type = "truncate-retry"
resolvers = ["cloudflare-udp"]
retry-resolver = "cloudflare-tcp"

[groups.cache]
type = "cache"
resolvers = ["retry"]

[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "cache"

[listeners.local-tcp]
address = "127.0.0.1:53"
protocol = "tcp"
resolver = "cache"
```

Example config files: [truncate-retry.toml](../cmd/routedns/example-config/truncate-retry.toml)

## Request Deduplication

The `request-dedup` element passes individual queries to its upstream resolver. While the first query is being processed, further queries for the same name will be blocked. Once the first query has been answered, all waiting queries are completed with the same answer. This element can be used to reduce load on upstream servers when queried by clients sending the same query multiple times.

### Configuration

To deduplicate queries, add an element with `type = "request-dedup"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.

### Examples

```toml
[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "cache"

[groups.cache]
type = "cache"
resolvers = ["dedup"]

[groups.dedup]
type = "request-dedup"
resolvers = ["cloudflare-udp"]

[resolvers.cloudflare-udp]
address = "1.1.1.1:53"
protocol = "udp"
```

Example config files: [request-dedup.toml](../cmd/routedns/example-config/request-dedup.toml)
