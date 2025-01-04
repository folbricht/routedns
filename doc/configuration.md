# RouteDNS Configuration Guide

## Table of contents

- [Overview](#overview)
  - [Split Configuration](#split-configuration)
  - [Regex Formatting](https://github.com/google/re2/wiki/Syntax)
- [Listeners](#listeners)
  - [Plain DNS](#plain-dns)
  - [DNS-over-TLS](#dns-over-tls)
  - [DNS-over-HTTPS](#dns-over-https)
  - [Oblivious DNS (ODoH)](#oblivious-dns-odoh)
  - [DNS-over-DTLS](#dns-over-dtls)
  - [DNS-over-QUIC](#dns-over-quic)
  - [Admin](#admin)
- [Modifiers, Groups and Routers](#modifiers-groups-and-routers)
  - [Cache](#cache)
  - [TTL Modifier](#ttl-modifier)
  - [Round-Robin group](#round-robin-group)
  - [Fail-Rotate group](#fail-rotate-group)
  - [Fail-Back group](#fail-back-group)
  - [Random group](#random-group)
  - [Fastest group](#fastest-group)
  - [Replace](#replace)
  - [Query Blocklist](#query-blocklist)
  - [Response Blocklist](#response-blocklist)
  - [Client Blocklist](#client-blocklist)
  - [EDNS0 Client Subnet modifier](#edns0-client-subnet-modifier)
  - [EDNS0 modifier](#edns0-modifier)
  - [Static Responder](#static-responder)
  - [Static Template Responder](#static-template-responder)
  - [Drop](#drop)
  - [Response Minimizer](#response-minimizer)
  - [Response Collapse](#response-collapse)
  - [Router](#router)
  - [Rate Limiter](#rate-limiter)
  - [Fastest TCP Probe](#fastest-tcp-probe)
  - [Retrying Truncated Responses](#retrying-truncated-responses)
  - [Request Deduplication](#request-deduplication)
  - [Syslog](#syslog)
- [Resolvers](#resolvers)
  - [Plain DNS](#plain-dns-resolver)
  - [DNS-over-TLS](#dns-over-tls-resolver)
  - [DNS-over-HTTPS](#dns-over-https-resolver)
  - [Oblivious DNS (ODoH)](#oblivious-DNS-ODoH)
  - [DNS-over-DTLS](#dns-over-dtls-resolver)
  - [DNS-over-QUIC](#dns-over-quic-resolver)
  - [Bootstrap Resolver](#bootstrap-resolver)
  - [SOCKS5 Proxy Support](#socks5-proxy-support)
- [Templates](#templates)

## Overview

RouteDNS uses a config file in [TOML](https://github.com/toml-lang/toml) format which is passed to the tool as argument on the command line. The configuration is broken up into sections, each of which can contain objects. Each element has a unique identifier (name) which is used to reference it from other objects in order to build a processing pipeline. A configuration can define elements in the following sections, in any order.

- `listeners` - [Listeners](#Listeners) are effectively DNS servers that receive queries from clients and form the starting point of a pipeline. Listeners are available for several different DNS protocols.
- `routers` - [Routers](#Router) can split a pipeline into multiple processing paths based on query properties such as name, type, or client information.
- `groups` - [Groups](#Modifiers-Groups-and-Routers) contain a range of failover and load-balancing algorithms as well as elements that modify queries or responses.
- `resolvers` - [Resolvers](#Resolvers) forward queries to upstream resolvers. They are in effect DNS client implementations that connect to other servers using a variety of protocols.

Not all of these are required to make a working configuration. A most basic configuration could contain a listener (receiver) and a resolver (sender) which would be a simple proxy. The listener and the resolver could use different protocols, making this proxy also a converter.

A more complex configuration could contain multiple listeners in different protocols, a router, several modifiers, and passing queries to multiple resolvers upstream, forming a pipeline like UDP listener -> router -> cache -> DoT resolver. A single configuration can hold more than one independent pipeline.

Below an example configuration that provides two local listeners, one for plain UDP, one for plain TCP. Each query passes through a router which splits the processing into 2 paths. One path for the client 192.168.1.123, and one for the rest. Queries from 192.168.1.123 are sent through a blocklist that filters out undesirable content before getting passed to the cleanbrowsing resolver using DNS-over-TLS while everyone else will get queries answered by Cloudflare unfiltered (also using DNS-over-TLS).

```toml
[resolvers.cleanbrowsing-dot]
address = "family-filter-dns.cleanbrowsing.org:853"
protocol = "dot"

[resolvers.cloudflare-dot]
address = "1.1.1.1:853"
protocol = "dot"

[groups.cleanbrowsing-filtered]
type = "blocklist-v2"
resolvers = ["cleanbrowsing-dot"]
blocklist = [
  '.evil.com',
  '.no-good.com',
]

[routers.router1]
routes = [
  { source = "192.168.1.123/32", resolver="cleanbrowsing-filtered" },
  { resolver="cloudflare-dot" },
]

[listeners.local-udp]
address = ":53"
protocol = "udp"
resolver = "router1"

[listeners.local-tcp]
address = ":53"
protocol = "tcp"
resolver = "router1"
```

More modifiers, groups or routers can be added to the pipeline (in any order). Objects reference each other by their identifiers which have to be unique in a given configuration.

### Split Configuration

Configuration can be broken up into individual files to support large or generated configurations. Split configuration files are passed as arguments to the application:

```text
routedns example-config/split-config/*.toml
```

The same constraints on unique identifiers apply in a split configuration. The individual files are effectively concatenated prior to being loaded.

Example [split-config](../cmd/routedns/example-config/split-config).

## Listeners

Listers are query receivers that form the start of a query pipeline. Queries received by a listener are then forwarded to routers, groups, or to resolvers directly. Several DNS protocols are supported.

While nothing in the configuration references a listener (since it's the first element in a pipeline), it still requires a name that is defined like so `[listeners.NAME]`.

Common options for all listeners:

- `address` - Listen address.
- `protocol` - The DNS protocol used to receive queries, can be `udp`, `tcp`, `dot`, `doh`, `doq`.
- `resolver` - Name/identifier of the next element in the pipeline. Can be a router, group, modifier or resolver.
- `allowed-net` - Array of network addresses that are allowed to send queries to this listener, in CIDR notation, such as `["192.167.1.0/24", "::1/128"]`. If not set, no filter is applied, all clients can send queries.

Secure listeners, such as DNS-over-TLS, DNS-over-HTTPS, DNS-over-DTLS, DNS-over-QUIC and Admin support additional options to configure certificate, keys and peer validation

- `server-crt` - Server certificate file. Required.
- `server-key` - Server key file. Required.
- `ca` - CA to validate client certificated. Optional. Uses the operating system's CA store by default.
- `mutual-tls` - Requires clients to send valid (as per `ca` option) certificates before establishing a connection. Optional.

The DNS-over-HTTPS listener also accepts the client IP address from trusted reverse proxies in a particular subnet. X-Forwarded-For headers are only used if they are provided from this subnet

- `trusted-proxy` - CIDR address of trusted reverse proxy. Optional.

### Plain DNS

Regular (insecure) DNS protocol over port 53, UDP and TCP. Setting `protocol` to `udp` will start a UDP listener, and `tcp` starts a TCP listener. In many cases both are present in a configuration if RouteDNS is used to provide DNS to local services over the loopback device.

Examples:

```toml
[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "router1"

[listeners.local-tcp]
address = "127.0.0.1:53"
protocol = "tcp"
resolver = "router1"
```

### DNS-over-TLS

DNS protocol using a TLS connection (DoT) as per [RFC7858](https://tools.ietf.org/html/rfc7858). Listeners are configured with `protocol = "dot"`.

Examples:

DoT listener accepting any client. Does not require client certificates and does not validate client certificates with a CA.

```toml
[listeners.local-dot]
address = ":853"
protocol = "dot"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
```

DoT listener enforcing mTLS and verifying client certificates with a CA.

```toml
[listeners.local-dot]
address = ":853"
protocol = "dot"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
ca = "/path/to/ca.crt"
mutual-tls = true
```

Example config files: [mutual-tls-dot-server.toml](../cmd/routedns/example-config/mutual-tls-dot-server.toml)

### DNS-over-HTTPS

As per [RFC8484](https://tools.ietf.org/html/rfc8484), DNS using the HTTPS protocol are configured with `protocol = "doh"`. By default, DoH uses TCP as transport, but it can also be run over QUIC by providing the option `transport = "quic"`. For TCP transport, TLS can be disabled with the `no-tls = true` option which can be used for testing or when the server is only accessible via reverse proxy that terminates TLS already.

Examples:

DoH listener accepting queries from any client.

```toml
[listeners.local-doh]
address = ":443"
protocol = "doh"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
```

DoH over QUIC listener.

```toml
[listeners.local-doh-quic]
address = ":1443"
protocol = "doh"
transport = "quic"
resolver = "cloudflare-dot"
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

DoH behind a reverse proxy. Clients are expected to connect to a reverse proxy in this subnet, which will provide their IP address in the X-Forwarded-For header. RouteDNS will trust this header from proxies in the subnet listed in `trusted-proxy`

```toml
[listeners.local-doh]
address = ":443"
protocol = "doh"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
frontend = { trusted-proxy = "192.168.1.0/24" }
```

Example config files: [mutual-tls-doh-server.toml](../cmd/routedns/example-config/mutual-tls-doh-server.toml), [doh-quic-server.toml](../cmd/routedns/example-config/doh-quic-server.toml), [doh-behind-proxy.toml](../cmd/routedns/example-config/doh-behind-proxy.toml), [doh-no-tls.toml](../cmd/routedns/example-config/doh-no-tls.toml)

### Oblivious DNS (ODoH)

ODoH ([draft](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh-03)) is intended to improve privacy of **clients** by encrypting queries for a **target** DNS server while sending the query through a **proxy**. In this configuration, neither the target nor the proxy can see the query content and the source IP of the client at the same time. A client query is resolved as follows:

- The client first queries the public key of the target resolver. This is a plain query that can be resolved by any resolver, but for privacy it's best to *not* use the target for this. RouteDNS always uses the proxy for this. The response is validated with DNSSEC.
- The client then encrypts the actual query with the public key of the target. A public key of the client is embedded in the encrypted message.
- The encrypted query message is sent to the proxy, with information about which target it should be forwarded.
- The target then encrypts the response with the client key and responds to the proxy, which then forwards the response to the client.
- The client decrypts the response it received from the proxy using its private key.

The ODoH resolver has all the configuration options as [DoH](#dns-over-https-resolver), with the configuration (endpoint, certs, mTLS, etc) for the proxy. In addition, a `target` option is available to specify the URL of the target. Configured with `protocol = "odoh"`.

Examples:

ODoH client using Cloudflare as proxy and target (since there aren't any other public proxies as of Dec 2020).

```toml
[resolvers.cloudflare-odoh-proxy]
address = "https://1.1.1.1/dns-query"
protocol = "odoh"
target = "https://odoh.cloudflare-dns.com/dns-query"
```

Example config files: [odoh-client.toml](../cmd/routedns/example-config/odoh-client.toml)

### DNS-over-DTLS

Similar to DoT, but uses a DTLS (UDP) connection as transport as per [RFC9894](https://tools.ietf.org/html/rfc8094). Configured with `protocol = "dtls"`.

Examples:

DTLS listener.

```toml
[listeners.local-dtls]
address = ":853"
protocol = "dtls"
resolver = "cloudflare-dot"
server-crt = "example-config/server-ec.crt"
server-key = "example-config/server-ec.key"
```

Example config files: [dtls-server.toml](../cmd/routedns/example-config/dtls-server.toml)

### DNS-over-QUIC

Similar to DoT, but uses a QUIC connection as transport as per [RFC9250](https://datatracker.ietf.org/doc/rfc9250/). Configured with `protocol = "doq"`. Note that this is different from DoH over QUIC. See [DNS-over-HTTPS](#DNS-over-HTTPS) for how to configure this.

Note: Support for the QUIC protocol is still experimental. For the purpose of DNS, there are two implementations, DNS-over-QUIC ([RFC9250](https://datatracker.ietf.org/doc/rfc9250/)) as well as DNS-over-HTTPS using QUIC. Both methods are supported by RouteDNS, client and server implementations.

Examples:

DoQ listener accepting queries from all clients.

```toml
[listeners.local-doq]
address = ":8853"
protocol = "doq"
resolver = "cloudflare-dot"
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

Example config files: [doq-listener.toml](../cmd/routedns/example-config/doq-listener.toml)

### Admin

The Admin listener provides metrics on RouteDNS usage and performance at https://{address}/routedns/vars/ in [expvar](https://pkg.go.dev/expvar) format. These metrics can be exported to be usable by Prometheus using [prometheus-expvar-exporter](https://github.com/albertito/prometheus-expvar-exporter). An example configuration is provided below.

Examples:

```toml
[listeners.local-admin]
address = "127.0.0.7:443"
protocol = "admin"
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

Example config files: [admin.toml](../cmd/routedns/example-config/admin.toml), [prometheus-exporter](../cmd/routedns/example-config/prometheus-exporter/)

## Modifiers, Groups and Routers

### Cache

A cache will store the responses to queries in memory and respond to further identical queries with the same response. To determine how long an item is kept in memory, the cache uses the lowest TTL of the RRs in the response. Responses served from the cache have their TTL updated according to the time the records spent in memory. If a query has an [ECS Subnet](https://tools.ietf.org/html/rfc7871) option, the subnet address forms part of they key to support subnet-specific answers.

Caches can be combined with a [TTL Modifier](#TTL-Modifier) to avoid too many cache-misses due to excessively low TTL values.

It is possible to pre-define a query name that will flush the cache if received from a client.

The content of memory caches can be persisted to and loaded from disk.

#### Configuration

Caches are instantiated with `type = "cache"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `cache-size` - Max number of responses to cache. Defaults to 0 which means no limit. Deprecated, set limit in the backend instead.
- `cache-negative-ttl` - TTL (in seconds) to apply to responses without a SOA. Default: 60. Optional
- `cache-rcode-max-ttl` - Map of RCODE to max TTL (in seconds) to use for records based on the status code regardless of SOA. Response codes are given in their numerical form: 0 = NOERROR, 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ... See [rfc2929#section-2.3](https://tools.ietf.org/html/rfc2929#section-2.3) for a more complete list. For example `{1 = 60, 3 = 60}` would set a limit on how long FORMERR or NXDOMAIN responses can be cached.
- `cache-answer-shuffle` - Specifies a method for changing the order of cached A/AAAA answer records. Possible values `random` or `round-robin`. Defaults to static responses if not set.
- `cache-harden-below-nxdomain` - Return NXDOMAIN for domain queries if the parent domain has a cached NXDOMAIN. See [RFC8020](https://tools.ietf.org/html/rfc8020).
- `cache-flush-query` - A query name (FQDN with trailing `.`) that if received from a client will trigger a cache flush (reset). Inactive if not set. Simple way to support flushing the cache by sending a pre-defined query name of any type. If successful, the response will be empty. The query will not be forwarded upstream by the cache.
- `cache-prefetch-trigger`- If a query is received for a record with less that `cache-prefetch-trigger` TTL left, the cache will send another, independent query to upstream with the goal of automatically refreshing the record in the cache with the response.
- `cache-prefetch-eligible` - Only records with at least `prefetch-eligible` seconds TTL are eligible to be prefetched.
- `backend` - Define what kind of storage is used for the cache. Contains multiple keys depending on type that can configure the behavior. Defaults to `memory` backend if not configued.

Backends:

**Memory backend**

The memory backend will keep all cache items in memory. It can be configured to write the content of the cache to disk on shutdown. Memory backend config has the following options:

- `type="memory"`
- `size` - Max number of responses to cache. Defaults to 0 which means no limit.
- `filename` - File to use for persistent storage to disk. The cache will be initialized with the content from the file and it'll write the content to the same file on shutdown. Defaults to no persistence
- `save-interval` - Interval (in seconds) to save the cache to file. Optional. If not set, the file is written only on shutdown.

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

#### Examples

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
backend = {type = "memory", filename = "/var/tmp/cache.json"}
```

Cache that is uses Redis as backend.

```toml
[groups.cloudflare-cached]
type = "cache"
resolvers = ["cloudflare-dot"]
cache-flush-query = "flush.cache."
backend = {type = "redis", redis-address = "127.0.0.1:6379", redis-key-prefix = "routedns-"}
```

Example config files: [cache.toml](../cmd/routedns/example-config/cache.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml), [cache-flush.toml](../cmd/routedns/example-config/cache-flush.toml), [cache-with-prefetch.toml](../cmd/routedns/example-config/cache-with-prefetch.toml), [cache-rcode.toml](../cmd/routedns/example-config/cache-rcode.toml), [cache-redis.toml](../cmd/routedns/example-config/cache-redis.toml)

### TTL modifier

A TTL modifier is used to adjust the time-to-live (TTL) of DNS responses. This is used to avoid frequently making the same queries to upstream because many responses have a value that is unreasonably low as outlined in this [blog](https://blog.apnic.net/2019/11/12/stop-using-ridiculously-low-dns-ttls). It's also possible to restrict very high TTL values that might be used in DNS poisoning attacks.

The limits are applied to all RRs in a response.

#### Configuration

Caches are instantiated with `type = "ttl-modifier"` in the groups section of the configuration.

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
- `ttl-max` - TTL minimum (in seconds) to apply to responses.

`ttl-min` and `ttl-max` are optional, but if configured define a floor/ceiling regardless of what `ttl-select` function is given.

#### Examples

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

### Round-Robin group

A Round-Robin balancer groups multiple upstream resolvers and sends every received query to the next resolver. It effectively balances the query load evenly over a number of upstream resolvers or modifiers.

#### Configuration

Round-Robin groups are instantiated with `type = "round-robin"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.

#### Examples

```toml
[groups.google-udp]
resolvers = ["google-udp-8-8-8-8", "google-udp-8-8-4-4"]
type = "round-robin"
```

### Fail-Rotate group

In a Fail-Rotate group, one of the upstream resolvers or modifiers is active and receives all queries. If the active resolver fails, i.e. no response or returns SERVFAIL, the next becomes active and the request is retried. If the last resolver fails the first becomes the active again. There's no time-based automatic fail-back.

#### Configuration

Round-Robin groups are instantiated with `type = "fail-rotate"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.
- `servfail-error` - If `true`, a SERVFAIL response from an upstream resolver is considered a failure triggering a switch to the next resolver. This can happen when DNSSEC validation fails for example. Default `false`.

#### Examples

```toml
[groups.google-udp]
resolvers = ["google-udp-8-8-8-8", "google-udp-8-8-4-4"]
type = "fail-rotate"
```

### Fail-Back group

Similar to [fail-rotate](#Fail-Rotate-group) but will attempt to fall back to the original order (prioritizing the first) if there are no failures for a minute. Failure means either no response or it returns SERVFAIL.

#### Configuration

Fail-Back groups are instantiated with `type = "fail-back"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers. The first in the array is the preferred resolver.
- `reset-after` - Time in seconds before switching from an alternative resolver back to the preferred resolver (first in the list), default 60. Note: This is not a timeout argument. After a failure of the preferred resolver, this defines the amount of time to use alternative/failover resolvers before switching back to the preferred. You can have as many resolvers in the array as the time limit allows.
- `servfail-error` - If `true`, a SERVFAIL response from an upstream resolver is considered a failure triggering a failover. This can happen when DNSSEC validation fails for example. Default `false`.

#### Examples

```toml
[groups.my-failback-group]
resolvers = ["company-dns", "cloudflare-dot"]
type = "fail-back"
```

### Random group

This group will pick a resolver from it's list of upstream resolvers at random. Resolvers that fail will be deactivated for an amount of time before being re-tried.

#### Configuration

Random groups are instantiated with `type = "random"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.
- `reset-after` - Time in seconds to disable a failed resolver, default 60.
- `servfail-error` - If `true`, a SERVFAIL response from an upstream resolver is considered a failure which will take the resolver temporarily out of the group. This can happen when DNSSEC validation fails for example. Default `false`.

#### Examples

```toml
[groups.random]
type   = "random"
resolvers = ["cloudflare-dot-1", "cloudflare-dot-2", "google-dot"]
```

Example config files: [random-resolver.toml](../cmd/routedns/example-config/random-resolver.toml)

### Fastest group

This group will send every query to all configured resolvers but only use the fastest (successful) response. Slower responses are discarded. Use sparingly as this increases the overall query load on upstream resolvers.

#### Configuration

Fastest groups are instantiated with `type = "fastest"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.

#### Examples

```toml
[groups.fastest]
type   = "fastest"
resolvers = ["cloudflare-dot-1", "cloudflare-dot-2", "google-dot"]
```

Example config files: [fastest.toml](../cmd/routedns/example-config/fastest.toml)

### Replace

The replace modifier applies regular expressions to query strings and replaces them before forwarding the query to the upstream resolver or modifier. The response is then mapped back to the original query, similar to NAT in a network. This can be useful to map hostnames to different domains on-the-fly or to append domain names to short hostname queries. In lab environments, one can replace a query for a production host with the equivalent lab host.

#### Configuration

Caches are instantiated with `type = "replace"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `replace` - Array of maps with `from` and `to` to represent the mapping.
  - `from` - Regular expression that is applied to the query name. Can contain regexp groups `(...)` which can be used in the `from` expression.
  - `to` - Expression to replace any matches in `from` with. Can reference regexp groups with `${1}`.

#### Examples

This replacer could be used where the company has multiple environment behind VPNs, each with their own DNS perhaps. Queries for hostnames like `nam-host-1`, `eu-host-5` or `ap-host-7` would have the appropriate full domain appended, and then possibly routed to the correct DNS (behind different VPNs). The router is not shown in this example.

```toml
[groups.internal-append-domain]
  type = "replace"
  resolvers = ["route-vpn"]
  replace = [
    { from = '^(nam-\d+\.)$', to = '${1}nam.internal.company.test.' },
    { from = '^(eu-\d+\.)$', to = '${1}eu.internal.company.test.' },
    { from = '^(ap-\d+\.)$', to = '${1}ap.internal.company.test.' },
  ]
```

### Query Blocklist

Query blocklists can be added to resolver-chains to prevent further processing of queries (return NXDOMAIN or spoofed IP) or to send queries to different resolvers if the query name matches a rule on the blocklist. A blocklist can have multiple rule-sets, with different formats. In its simplest form, the blocklist has just one upstream resolver and forwards anything that does not match its rules. If a query matches, it'll be answered with NXDOMAIN or a spoofed IP, depending on what blocklist format is used.

The blocklist group supports 3 types of blocklist formats:

- `regexp` - The entire query string is matched against a list of regular expressions and NXDOMAIN returned if a match is found.
- `domain` - A list of domains with some wildcard capabilities. Also results in an NXDOMAIN. Entries in the list are matched as follows:
  - `domain.com` matches just domain.com and no sub-domains.
  - `.domain.com` matches domain.com and all sub-domains.
  - `*.domain.com` matches all subdomains but not domain.com. Only one wildcard (at the start of the string) is allowed.
- `hosts` - A blocklist in hosts-file format. If a non-zero IP address is provided for a record, the response is spoofed rather than returning NXDOMAIN.

In addition to reading the blocklist rules from the configuration file, routedns supports reading from the local filesystem and from remote servers via HTTP(S). Use the `blocklist-source` property of the blocklist to provide a list of blocklists of different formats, either local files or URLs. The `blocklist-refresh` property can be used to specify a reload-period (in seconds). If no `blocklist-refresh` period is given, the blocklist will only be loaded once at startup. The following example loads a regexp blocklist via HTTP once a day.

To override the blocklist filtering behavior, the properties `allowlist`, `allowlist-format`, `allowlist-source` and `allowlist-refresh` can be used to define inverse filters. They are used just like the equivalent blocklist-options, but are effectively inverting its behavior. A query matching a rule on the allowlist will be passing through the blocklist and not be blocked.

#### Configuration

Query blocklists are instantiated with `type = "blocklist-v2"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `blocklist-resolver` - Alternative resolver for queries matching the blocklist, rather than responding with NXDOMAIN. Optional.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided. Can be `regexp`, `domain`, or `hosts`. Defaults to `regexp`.
- `blocklist-refresh` - Time interval (in seconds) in which external (remote or local) blocklists are reloaded. Optional.
- `blocklist-source` - An array of blocklists, each with `format`, `source` and optionally `name`.
- `allowlist-resolver` - Alternative resolver for queries matching the allowlist, rather than forwarding to the default resolver.
- `allowlist-format` - The format the allowlist is provided in. Only used if `allowlist-source` is not provided. Can be `regexp`, `domain`, or `hosts`. Defaults to `regexp`.
- `allowlist-refresh` - Time interval (in seconds) in which external allowlists are reloaded. Optional.
- `allowlist-source` - An array of allowlists, each with `format`, `source`, and optionally `cache-dir` or `allow-failure`.
- `edns0-ede` - Optional, include an extended error code in the response if it's blocked. Only used when the response is blocked, not when it's spoofed. The value is a struct with two keys, `code` (number) and `text` (string). Possible values for `code` are defined in [rfc8914](https://datatracker.ietf.org/doc/html/rfc8914) while `text` can carry additional information that is displayed by `dig` for example. The `text` value is a template that has access to a number of fields of query to allow customizing the response based on data in the query. See [Templates](#templates) for details. Simple placeholders in `text` would be `{{ .Question }}` for the question in the query or `{{ .ID }}` to be replaced with the query ID.

When using the `cache-dir` option on a list that loads rules via HTTP, the results are cached into a file in the given directory. The filename is the URL of the source hashed with SHA256 so multiple blocklists can be cached in the same directory. If a cached file exists on startup, it is used instead of refreshing the list from the remote location (slowing down startup).

To avoid errors at startup when for example a remote blocklist isn't available, the `allow-failure` option can be used. Any errors encountered will be logged but not cause a failure to start. If a failure occurs during runtime, the previous ruleset will be reused.

#### Examples

Simple blocklist with static regexp rules defined in the configuration:

```toml
[groups.my-blocklist]
type             = "blocklist-v2"
resolvers        = ["upstream-resolver"] # Anything that passes the filter is sent on to this resolver
blocklist-format ="regexp"               # "domain", "hosts" or "regexp", defaults to "regexp"
blocklist        = [                     # Define the names to be blocked
  '(^|\.)evil\.com\.$',
  '(^|\.)unsafe[123]\.org\.$',
]
```

Simple blocklist with static `domain`-format rule in the configuration. This will respond with an extended error code and a message containing the question name.

```toml
[groups.my-blocklist]
type             = "blocklist-v2"
resolvers        = ["upstream-resolver"]
blocklist-format = "domain"
edns0-ede        = {code = 15, text = "Blocked {{ .Question }} because rule {{ .BlocklistRule }} on {{ .Blocklist}}"}
blocklist = [
  'domain1.com',               # Exact match
  '.domain2.com',              # Exact match and all sub-domains
  '*.domain3.com',             # Only match sub-domains
]
```

A blocklist of type `hosts` can be used to spoof IP addresses:

```toml
[groups.my-blocklist]
type             = "blocklist-v2"
resolvers        = ["upstream-resolver"]
blocklist-format = "hosts"
blocklist = [
  '127.0.0.1 www.domain1.com',  # Spoofed
  '0.0.0.0   www.domain2.com',  # NXDOMAIN if matched
]
```

Blocklist that loads two rule-sets. One from an HTTP server, the other from a file on disk. Both are reloaded once a day. A `name` can be provided which will be used in logs instead of `source`.

```toml
[groups.cloudflare-blocklist]
type = "blocklist-v2"
resolvers = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source = [
   {name = "cbuijs/blocklist" format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/master/deugniets/routedns.blocklist.domain.list"},
   {format = "regexp", source = "/path/to/local/regexp.list"},
]
```

Remote blocklist that is cached to local disk (`cache-dir="/var/tmp"`) and loaded from it at startup. It also ignores failures to load the remote blocklist and does not prevent startup.

```toml
[groups.cloudflare-blocklist]
type = "blocklist-v2"
resolvers = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source = [
   {format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/master/deugniets/routedns.blocklist.domain.list", cache-dir = "/var/tmp", allow-failure = true},
]
```

Blocklist that loads 2 remote blocklists daily, and also defines a local allowlist which overrides the blocklist rules. Anything matching a rule on the allowlist is forwarded to an alternative resolver or modifier, `"trusted-resolver"` in this case (not shown in the example).

```toml
[groups.cloudflare-blocklist]
type = "blocklist-v2"
resolvers = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source = [
   {format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/master/deugniets/routedns.blocklist.domain.list"},
   {format = "regexp", source = "https://raw.githubusercontent.com/cbuijs/accomplist/master/deugniets/routedns.blocklist.regexp.list"},
]
allowlist-resolver = "trusted-resolver" # Send anything on the allowlist to a different upstream resolver (optional)
allowlist-refresh = 86400
allowlist-source = [
   {format = "domain", source = "/path/to/trustworthy.list"},
]
```

Example config files: [blocklist-regexp.toml](../cmd/routedns/example-config/blocklist-regexp.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml), [blocklist-domain.toml](../cmd/routedns/example-config/blocklist-domain.toml), [blocklist-hosts.toml](../cmd/routedns/example-config/blocklist-hosts.toml), [blocklist-local.toml](../cmd/routedns/example-config/blocklist-local.toml), [blocklist-remote.toml](../cmd/routedns/example-config/blocklist-remote.toml), [blocklist-allow.toml](../cmd/routedns/example-config/blocklist-allow.toml), [blocklist-resolver.toml](../cmd/routedns/example-config/blocklist-resolver.toml), [blocklist-domain-ede.toml](../cmd/routedns/example-config/blocklist-domain-ede.toml)

### Response Blocklist

Rather than filtering queries, response blocklists evaluate the response to a query and block anything that matches a filter-rule. There are two kinds of response blocklists: `response-blocklist-ip` and `response-blocklist-name`.

- `response-blocklist-ip` blocks backed on IP addresses in the response, by network IP (in CIDR notation) or geographical location.
- `response-blocklist-name` filters based on domain names in CNAME, MX, NS, PRT and SRV records.

#### Configuration

The configuration options of response blocklists are very similar to that of [query blocklists](#Query-Blocklist) with the exception of the `allowlists-*` options which are not supported in response blocklists.

Response blocklists are instantiated with `type = "response-blocklist-ip"` or `type = "response-blocklist-name"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `blocklist-resolver` - Alternative resolver for responses matching a rule, the query will be re-sent to this resolver. Optional.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided.
  - For `response-blocklist-ip`, the value can be `cidr`, or `location`. Defaults to `cidr`.
  - For `response-blocklist-name`, the value can be `regexp`, `domain`, or `hosts`. Defaults to `regexp`.
- `blocklist-refresh` - Time interval (in seconds) in which external (remote or local) blocklists are reloaded. Optional.
- `blocklist-source` - An array of blocklists, each with `format`, `source` and optionally `cache-dir` (see notes for [Query Blockists](#Query-Blocklist)) as well as `name` which assigns a name to the list used in logs (defaults to `source`).
- `filter` - If set to `true` in `response-blocklist-ip`, matching records will be removed from responses rather than the whole response. If there is no answer record left after applying the filter, NXDOMAIN will be returned unless an alternative `blocklist-resolver` is defined.
- `inverted` - Inverts the behavior of the blocklist. If set to `true`, only IPs that are on the blocklist are allowed and responses containing an IP not on the blocklist are blocked. Can be combined with `filter` to remove any IPs not on the blocklist from the response.
- `location-db` - If location-based IP blocking is used, this specifies the GeoIP data file to load. Optional. Defaults to /usr/share/GeoIP/GeoLite2-City.mmdb
- `edns0-ede` - Optional, include an extended error code in the response if it's blocked. Only used when the response is blocked, not when it's spoofed. The value is a struct with two keys, `code` (number) and `text` (string). Possible values for `code` are defined in [rfc8914](https://datatracker.ietf.org/doc/html/rfc8914) while `text` can carry additional information that is displayed by `dig` for example. The `text` value is a template that has access to a number of fields of query to allow customizing the response based on data in the query. See [Templates](#templates) for details. Simple placeholders in `text` would be `{{ .Question }}` for the question in the query or `{{ .ID }}` to be replaced with the query ID.

Location-based blocking requires a list of GeoName IDs of geographical entities (Continent, Country, City or Subdivision) and the GeoName ID, like `2750405` for Netherlands. The GeoName ID can be looked up in [https://www.geonames.org/](https://www.geonames.org/). Locations are read from a MAXMIND GeoIP2 database that either has to be present in `/usr/share/GeoIP/GeoLite2-City.mmdb` or is configured with the `location-db` option.

Examples:

Simple response blocklists with static rules in the configuration file.

```toml
[groups.cloudflare-blocklist]
type                = "response-blocklist-ip"
resolvers           = ["cloudflare-dot"]
blocklist           = [
  '127.0.0.0/24',
  '157.240.0.0/16',
]
```

```toml
[groups.cloudflare-blocklist]
type             = "response-blocklist-name"
resolvers        = ["cloudflare-dot"]
blocklist-format = "domain"
blocklist        = [
  'ns.evil.com',
  '*.acme.test',
]
```

Response blocklists that use local or remote rule-sets with periodic refresh.

```toml
[groups.cloudflare-blocklist]
type              = "response-blocklist-ip"
resolvers         = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source  = [
  {source = "./example-config/cidr.txt"},
  {source = "https://host/block.cidr.txt"},
]
```

```toml
[groups.cloudflare-blocklist]
type              = "response-blocklist-name"
resolvers         = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source  = [
  {format = "domain", source = "./example-config/domains.txt"},
]
```

Response blocklist that is cached on local disk for faster startup. By default, logs will contain the source (in this case the URL) of a match, but different name can be specified with `name`.

```toml
[groups.cloudflare-blocklist]
type              = "response-blocklist-ip"
resolvers         = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source  = [
  {name = "my-block-list", source = "https://host/block.cidr.txt", cache-dir="/var/tmp"},
]
```

Response blocklist based on IP geo-location. Remote and multiple blocklists are supported as well.

```toml
[groups.cloudflare-blocklist]
type                = "response-blocklist-ip"
resolvers           = ["cloudflare-dot"]
blocklist-format    = "location"
blocklist           = [
  "6255148", # Europe
  "2017370", # Russia
  "7839805", # Melbourne
]
```

Example config files: [response-blocklist-ip.toml](../cmd/routedns/example-config/response-blocklist-ip.toml), [response-blocklist-name.toml](../cmd/routedns/example-config/response-blocklist-name.toml), [response-blocklist-ip-remote.toml](../cmd/routedns/example-config/response-blocklist-ip-remote.toml), [response-blocklist-name-remote.toml](../cmd/routedns/example-config/response-blocklist-name-remote.toml), [response-blocklist-ip-resolver.toml](../cmd/routedns/example-config/response-blocklist-ip-resolver.toml), [response-blocklist-name-resolver.toml](../cmd/routedns/example-config/response-blocklist-name-resolver.toml), [response-blocklist-geo.toml](../cmd/routedns/example-config/response-blocklist-geo.toml)

### Client Blocklist

Client blocklists match the IP of the client instead of responses. By default, a client on the blocklist will receive a REFUSED, though other responses can be configured by combining it with a `static-responder` The same options as with [response-blocklist-ip](#Response-blocklist) are supported. This includes CIDR lists, static in configuration, on local disk or remote via HTTP. Also, geo location based blocklists are supported.

#### Configuration

The configuration options of client blocklists are very similar to that of [query blocklists](#Response-Blocklist) with the exception of the `filter` option.

Client blocklists are instantiated with `type = "client-blocklist"`.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `blocklist-resolver` - Alternative resolver for responses matching a rule, the query will be re-sent to this resolver. Optional.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided. Values can be `cidr`, or `location`. Defaults to `cidr`.
- `blocklist-refresh` - Time interval (in seconds) in which external (remote or local) blocklists are reloaded. Optional.
- `blocklist-source` - An array of blocklists, each with `format` and `source` and optionally `name`.
- `location-db` - If location-based IP blocking is used, this specifies the GeoIP data file to load. Optional. Defaults to /usr/share/GeoIP/GeoLite2-City.mmdb

Examples:

Simple client blocklists that responds with DROP to all queries from one network source

```toml
[groups.cloudflare-blocklist]
type                = "client-blocklist"
resolvers           = ["cloudflare-dot"]
blocklist           = [
  '157.240.0.0/16',
]
```

This client blocklist uses the `blocklist-resolver` option to send queries from matching clients to a resolver that drops the query.

```toml
[groups.cloudflare-blocklist]
type                = "client-blocklist"
resolvers           = ["cloudflare-dot"]
blocklist-resolver  = "drop-all"
blocklist           = [
  '157.240.0.0/16',
]

[groups.drop-all]
type = "drop"
```

Example config files: [client-blocklist.toml](../cmd/routedns/example-config/client-blocklist.toml), [client-blocklist-refused.toml](../cmd/routedns/example-config/client-blocklist-refused.toml), [client-blocklist-geo.toml](../cmd/routedns/example-config/client-blocklist-geo.toml)

### EDNS0 Client Subnet Modifier

A client subnet modifier is used to either remove ECS options from a query, replace/add one, or improve privacy by hiding more bits of the address. The following operation are supported by the subnet modifier:

- `add` - Add an ECS option to a query. If there is one already it is replaced. If no `ecs-address` is provided, the address of the client is used (with `ecs-prefix4` or `ecs-prefix6` applied).
- `add-if-missing` - Add an ECS option to a query if none was provided by the client. If no `ecs-address` is provided, the address of the client is used (with `ecs-prefix4` or `ecs-prefix6` applied).
- `delete` - Remove the ECS option completely from the EDNS0 record.
- `privacy` - Restrict the number of bits in the address to the number in `ecs-prefix4`/`ecs-prefix6`.

#### Configuration

Client Subnet modifiers are instantiated with `type = "ecs-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `ecs-op` - Operation to be performed on query options. Either `add`, `add-if-missing`, `delete`, or `privacy`. Does nothing if not specified.
- `ecs-address` - The address to use in the option. Only used for add operations. If given, will set the address to a fixed value. If missing, the address of the client is used (with the appropriate `ecs-prefix` applied).
- `ecs-prefix4` and `ecs-prefix6` - Source prefix length. Mask for the address. Only used for add and privacy operations.

Examples:

Remove ECS options from all queries.

```toml
[groups.google-ecs]
type = "ecs-modifier"
resolvers = ["google-dot"]
ecs-op = "delete" # "add", "delete", "privacy". Defaults to "" which does nothing.
```

Add/replace ECS options in all queries with a fixed network address. Without `ecs-address`, this will use the client's IP address.

```toml
[groups.google-ecs]
type = "ecs-modifier"
resolvers = ["google-dot"]
ecs-op = "add"
ecs-address = "1.2.3.4"
ecs-prefix4 = 24
```

Restrict the number of bits in the address in queries to upstream resolvers.

```toml
[groups.google-ecs]
type = "ecs-modifier"
resolvers = ["google-dot"]
ecs-op = "privacy"
ecs-prefix4 = 8
ecs-prefix6 = 64
```

Example config files: [ecs-modifier-add.toml](../cmd/routedns/example-config/ecs-modifier-add.toml), [ecs-modifier-delete.toml](../cmd/routedns/example-config/ecs-modifier-delete.toml), [ecs-modifier-privacy.toml](../cmd/routedns/example-config/ecs-modifier-privacy.toml)

### EDNS0 Modifier

EDNS0 Modifier allows low-level operations on the EDNS0 option records in queries. It can be used to add or remove custom option codes with arbitrary data.

- `add` - Add an EDNS0 option to a query. If there is one already it is replaced.
- `delete` - Remove the specified option from the EDNS0 options.

#### Configuration

EDNS0 Subnet modifiers are instantiated with `type = "edns0-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `edns0-op` - Operation to be performed on query options. Either `add`, `delete`. Note that `add` replaces options with the same code if present.
- `edns0-code` - EDNS0 option code to apply the modification to.
- `edns0-data` - Raw data for the option expressed in an array of (decimal!) byte values. Only used for `add` operations.

Examples:

Add the MAC address 52:54:00:b6:49:60 to an EDNS0 option (code 65001) for identification with the upstream resolver.

```toml
[groups.opendns-mac]
type = "edns0-modifier"
resolvers = ["opendns"]
edns0-op = "add" # "add" or "delete". Defaults to "" which does nothing.
edns0-code = 65001
edns0-data = [82, 84, 0, 182, 73, 96]
```

Example config files: [edns0-modifier.toml](../cmd/routedns/example-config/edns0-modifier.toml)

### Static responder

A static responder can be used to terminate every query made to it with a fixed answer. The answer can contain Answer, NS, and Extra records with a configurable RCode. Static responders are useful in combination with routers to build walled-gardens or blocklists providing more control over the response. The individual records in the response are defined in zone-file format. The default TTL is 1h unless given in the record.

#### Configuration

Round-Robin groups are instantiated with `type = "static-responder"` in the groups section of the configuration.

Options:

- `rcode` - Response code: 0 = NOERROR, 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ... See [rfc2929#section-2.3](https://tools.ietf.org/html/rfc2929#section-2.3) for a more complete list. Defaults to 0 (No Error).
- `answer` - Array of strings, each one representing a line in zone-file format. Forms the content of the Answer records in the response. The name in all answer records is replaced with the name in the query to create a match.
- `ns` - Array of strings, each one representing a line in zone-file format. Forms the content of the Authority records in the response.
- `extra` - Array of strings, each one representing a line in zone-file format.  Forms the content of the Additional records in the response.
- `truncate` - when true, TC Bit is set in response. Default is false.
- `edns0-ede` - Optional, include an extended error code in the response if it's blocked. Only used when the response is blocked, not when it's spoofed. The value is a struct with two keys, `code` (number) and `text` (string). Possible values for `code` are defined in [rfc8914](https://datatracker.ietf.org/doc/html/rfc8914) while `text` can carry additional information that is displayed by `dig` for example. The `text` value is a template that has access to a number of fields of query to allow customizing the response based on data in the query. See [Templates](#templates) for details. Simple placeholders in `text` would be `{{ .Question }}` for the question in the query or `{{ .ID }}` to be replaced with the query ID.

Note:

The default TTL of all records is 3600 unless provided in the configuration. To set the TTL in the answer, provide a placeholder for the name like so: `". 86400 IN A 1.2.3.4"`. Starting the line with the TTL value will not work.

Examples:

A fixed responder that will return a full answer with NS and Extra records with different TTL. The name string in answer records gets updated dynamically to match the query, while NS and Extra records are return unmodified.

```toml
[groups.static-a]
type   = "static-responder"
answer = ["IN A 1.2.3.4"]
ns = [
    "domain.com. 18000 IN NS ns1.domain.com.",
    "domain.com. 18000 IN NS ns2.domain.com.",
]
extra = [
    "ns1.domain.com. 1800 IN A 127.0.0.1",
    "ns1.domain.com. 1800 IN AAAA ::1",
    "ns2.domain.com. 1800 IN A 127.0.0.1",
    "ns2.domain.com. 1800 IN AAAA ::1",
]
```

Simple responder that'll reply with SERVFAIL to every query routed to it.

```toml
[groups.static-servfail]
type  = "static-responder"
rcode = 2 # SERVFAIL
```

Blocks requests for QTYPE ANY RRs by using a router and a static responder. The router sends all ANY queries to the static responder which replies with an HINFO RR.

```toml
[groups.static-rfc8482]
type   = "static-responder"
answer = ["IN HINFO RFC8482 ANY obsoleted!"]

[routers.my-router]
routes = [
  { type = "ANY", resolver="static-rfc8482" }, # Send queries of type ANY to a static responder
  { resolver = "cloudflare-dot" },             # All other queries are forwarded
]
```

Return an empty answer with TC (Truncate) bit set so the DNS client is instructed to retry the query using TCP instead of UDP.

```toml
[groups.static-truncate]
type     = "static-responder"
rcode    = 0 # NOERROR
truncate = True
```

Return an extended error code explaining why a query was blocked.

```toml
[groups.static]
type  = "static-responder"
edns0-ede = {code = 15, text = "Blocked because reasons"}
```

Example config files: [walled-garden.toml](../cmd/routedns/example-config/walled-garden.toml), [rfc8482.toml](../cmd/routedns/example-config/rfc8482.toml), [static-extended-error.toml](../cmd/routedns/example-config/static-extended-error.toml)

### Static Template Responder

A static template responder operates similarly to a [Static Responder](#static-responder) with the main difference being that the records configured are templates, meaning they can contain placeholders which can refer to data in the query, such as the question. Based on the values in the question, the template can manipulate the response. Templates can contain more complex operations such as string splitting, replacing etc.

#### Configuration

See [Static Responder](#static-responder) for a list of options. The values are the same except that the string values are treated as [templates](#templates).

Examples:

A fixed responder that can respond to queries like `192.168.1.12.rebind.` by striping the `.rebind.` suffix and treating the remaining string as IP. Note that the template in this case has to produce a valid IP or it will fail. To ensure the queries reaching this responder are always valid it may be best to combine with a router or blocklist in front of it.

```toml
[groups.static]
type   = "static-template"
answer = [
    '{{ .Question }} IN A {{ trimSuffix .Question ".rebind."}}'
]
```

Same as above but converts `192-168-1-12.rebind` into an IP.

```toml
[groups.static]
type   = "static-template"
answer = [
  '{{ .Question }} {{ .QuestionClass }} {{ .QuestionType }} {{ replaceAll ( index ( split .Question "." ) 0 ) "-" "." }}'
]
```

Return an extended error code explaining why a query was blocked.

```toml
[groups.static]
type   = "static-template"
edns0-ede = {code = 15, text = '{{ .Question }} is banned!'}
```

Example config files: [static-template.toml](../cmd/routedns/example-config/static-template.toml), [static-template-error.toml](../cmd/routedns/example-config/static-template-error.toml)

### Drop

Terminates a pipeline by dropping the request. Typically used with blocklists to abort queries that match block rules. UDP and TCP listeners close the connection without replying, while HTTP listeners will reply with an HTTP error.

#### Configuration

A drop group is instantiated with `type = "drop"` in the groups section of the configuration.

Examples:

Client blocklist that drops requests from clients on the blocklist.

```toml
[groups.cloudflare-blocklist]
type                = "client-blocklist"
resolvers           = ["cloudflare-dot"]
blocklist-resolver  = "drop" # Any match is sent to a resolver that drops the query
blocklist           = [
  '157.240.0.0/16',
]

[groups.drop]
type = "drop"

```

Example config files: [client-blocklist-drop.toml](../cmd/routedns/example-config/client-blocklist-drop.toml)

### Response Minimizer

This element passes all queries to its upstream resolver and strips all Extra and NS records from the response, making responses smaller.

#### Configuration

A response minimizer is instantiated with `type = "response-minimize"` in the groups section of the configuration.

Examples:

```toml
[groups.minimize]
type = "response-minimize"
resolvers = ["google-dot"]
```

Example config files: [response-minimize.toml](../cmd/routedns/example-config/response-minimize.toml)

### Response Collapse

This element passes all queries to its upstream resolver and collapses response chains in the answer records to just the query name and the queried type.

A response chain like this:

```text
www.paypal.com. 2964 IN CNAME www.glb.paypal.com.
www.glb.paypal.com. 251 IN CNAME www.paypal.com-a.edgekey.net.
www.paypal.com-a.edgekey.net. 7199 IN CNAME e5308.x.akamaiedge.net.
e5308.x.akamaiedge.net. 18 IN A 95.100.196.60
```

Becomes:

```text
www.paypal.com. 18 IN A 95.100.196.60
```

#### Configuration

A response collapse element is instantiated with `type = "response-collapse"` in the groups section of the configuration.

Options:

- `null-rcode` - Response code if after collapsing there are no answer records left: 0 = NOERROR (default), 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ... See [rfc2929#section-2.3](https://tools.ietf.org/html/rfc2929#section-2.3)

Examples:

```toml
[groups.collapse]
type = "response-collapse"
resolvers = ["google-dot"]
```

Example config files: [response-collapse.toml](../cmd/routedns/example-config/response-collapse.toml)

### Router

Routers are used to direct queries to specific upstream resolvers, modifiers, or to other routers based on the query type, name, time of day, or client information. Each router contains at least one route. Routes are are evaluated in the order they are defined and the first match will be used. Routes that match on the query name are regular expressions. Typically the last route should not have a class, type or name, making it the default route.

#### Configuration

Routers groups are instantiated with `routers.NAME` with NAME being a unique identifier for this router.

Options:

- `routes` - Array of routes. Routes are processed in order and processing stops after the first match.

A route has the following fields:

- `type` - If defined, only matches queries of this type, `A`, `AAAA`, `MX`, etc. Optional.
- `types` - List of types. If defined, only matches queries whose type is in this list. Optional.
- `class` - If defined, only matches queries of this class (`IN`, `CH`, `HS`, `NONE`, `ANY`). Optional.
- `name` - A regular expression that is applied to the query name. Note that dots in domain names need to be escaped. Optional.
- `source` - Network in CIDR notation. Used to route based on client IP. Optional.
- `weekdays` - List of weekdays this route should match on. Possible values: `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`. Uses local time, not UTC.
- `after` - Time of day in the format HH:mm after which the rule matches. Uses 24h format. For example `09:00`. Note that together with the `before` parameter it is possible to accidentally write routes that can never trigger. For example `after=12:00 before=11:00` can never match as both conditions have to be met for the route to be used.
- `before` - Time of day in the format HH:mm before which the rule matches. Uses 24h format. For example `17:30`.
- `invert` - Invert the result of the matching if set to `true`. Optional.
- `doh-path` - Regexp that matches on the DoH query path the client used.
- `listener` - Regexp that matches on the ID of the listener that first received.
- `servername` - Regexp that matches on the TLS server name used in the TLS handshake with the listener.
- `resolver` - The identifier of a resolver, group, or another router. Required.

Examples:

Sends all queries for the MX record of `google.com` and all its sub-domains to a group consisting of Google's DNS servers. Anything else is sent to a DNS-over-TLS resolver.

```toml
[routers.router1]
routes = [
  { name = '(^|\.)google\.com\.$', type = "MX", resolver="google-udp" },
  { resolver="cloudflare-dot" }, # default route
]
```

Send all queries for A, AAAA, and MX records under `google.com` to a non-default resolver. Note the plural in `types` which expects a list.

```toml
[routers.router1]
routes = [
  { name = '(^|\.)google\.com\.$', types = ["A", "AAAA", "MX"], resolver="google-udp" },
  { resolver="cloudflare-dot" }, # default route
]
```

Route queries from a specific IP to a different resolver.

```toml
[routers.router1]
routes = [
  { source = "192.168.1.123/32", resolver="cleanbrowsing-filtered" },
  { resolver="cloudflare-dot" },
]
```

Disallow all queries for records that are not of type A, AAAA, or MX by responding with NXDOMAIN.

```toml
[routers.router1]
routes = [
  { invert = true, types = ["A", "AAAA", "MX"], resolver="static-nxdomain" },
  { resolver="cloudflare-dot" },
]

[groups.static-nxdomain]
type  = "static-responder"
rcode = 3
```

Use a different upstream resolver on weekends between 9am and 5pm.

```toml
[routers.router1]
routes = [
  { weekdays = ["sat", "sun"], after = "09:00", before = "17:00", resolver="google-dot" },
  { resolver="cloudflare-dot" },
]
```

Example config files: [split-dns.toml](../cmd/routedns/example-config/split-dns.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml), [family-browsing.toml](../cmd/routedns/example-config/family-browsing.toml), [walled-garden.toml](../cmd/routedns/example-config/walled-garden.toml), [router.toml](../cmd/routedns/example-config/router.toml), [router-time.toml](../cmd/routedns/example-config/router-time.toml)

### Rate Limiter

This element is used to limit the number of queries a client or network is allowed to make in a given time period. It uses a fixed window algorithm and by default drops any queries that exceed the configured maximum. Alternatively, a `limit-resolver` can be configured to route such queries to other elements such as [static responders](#Static-responder) or other resolvers.

#### Configuration

A rate limiter element is instantiated with `type = "rate-limiter"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `limit-resolver` - Upstream element to route rate-limited requests to. Optional, default behavior is to drop such queries.
- `requests` - Number of requests allowed per time period.
- `window` - Number of seconds in the time period, default 60.
- `prefix4` - Prefix length for identifying an IPv4 client, default 24
- `prefix6` - Prefix length for identifying an IPv6 client, default 56

Examples:

Simple rate-limiter allowing 200 requests per minute from the same /24 (or /56) networks.

```toml
[groups.rrl]
type = "rate-limiter"
resolvers = ["cloudflare-dot"]
requests = 200
```

Rate-limiter allowing 100 queries from a /24 (or /56) network per 2 minutes. Queries that exceed the limit will be answered with REFUSED.

```toml
[groups.rrl]
type = "rate-limiter"
resolvers = ["cloudflare-dot"]
limit-resolver = "static-refused"
requests = 100
window = 120
prefix4 = 24
prefix6 = 56

[groups.static-refused]
type  = "static-responder"
rcode = 5 # REFUSED
```

Example config files: [rate-limiter.toml](../cmd/routedns/example-config/rate-limiter.toml)

### Fastest TCP Probe

The `fastest-tcp` element will first perform a lookup, then send TCP probes to all A or AAAA records in the response. It can then either return just the A/AAAA record for the fastest response, or all A/AAAA sorted by response time (fastest first). Since probing multiple servers can be slow, it is typically used behind a [cache](#Cache) to avoid making too many probes repeatedly. Each instance can only probe one port and if different ports are to be probed depending on the query name, a router should be used in front of it as well.

#### Configuration

A Fastest TCP Probe element is instantiated with `type = "fastest-tcp"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `port` - TCP port number to probe. Default: `443`.
- `wait-all` - Instead of just returning the fastest response, wait for all probes and return them sorted by response time (fastest first). This will generally be slower as the slowest TCP probe determines the query response time. Default: `false`
- `success-ttl-min` - Minimum TTL of successful probes (in seconds). Default: 0. Similar to the `ttl-min` option of [TTL Modifier](#TTL-modifier). Typically used to cache the response for longer given how resource-intensive and slow probing can be.

Examples:

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

### Retrying Truncated Responses

The `truncated-retry` element will first perform a lookup using its primary resolver. If the response from the primary is truncated, the same query is retried with the secondary `retry-resolver`. This element is only useful if the primary resolver uses either plain UDP or DTLS as those apply limits to the size of the response. In addition, it is typically used behind a [cache](#Cache) which can then store the full response and respond faster to clients which too may have to retry the query if using a UDP or DTLS listener.

#### Configuration

To support switching to streaming resolvers on truncation, add an element with `type = "truncate-retry"` in the groups section of the configuration, right before the resolver.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `retry-resolver` - Must be referencing another resolver, typically using a stream-protocol such as TCP, DoH, or DoT.

Examples:

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

# Try UDP first, if truncated use the alernative (TCP)
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

### Request Deduplication

The `request-dedup` element passes individual queries to its upstream resolver. While the first query is being processed, further queries for the same name will be blocked. Once the first query has been answered, all waiting queries are completed with the same answer. This element can be used to reduce load on upstream servers when queried by clients sending the same query multiple times.

#### Configuration

To deduplicate queries, add an element with `type = "request-dedup"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.

Examples:

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

### Syslog

The `syslog` element can be used to log requests and/or responses to local or remote syslog servers. It forwards queries un-modified to the configured resolver. It is possible to configure multiple syslog loggers in different places. For example a logger could be configured to log and forward queries for domains on a blocklist, or behind a router.

#### Configuration

To enable syslog, add an element with `type = "syslog"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `network` - Network protocol. `udp`, `tcp` or `unix`. Defaults to `unix`.
- `address` - Remote syslog server address and port. For example `192.168.0.1:514`
- `priority` - Syslog priority. Possible values: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`
- `tag` - Syslog tag. Defaults to the program name.
- `log-request` - Enable logging of requests. Default `false`.
- `log-response` - Enable logging of responses. Default `false`.
- `verbose` - Log all answers, not just the types that match the query. Default `false`.

Examples:

```toml
[groups.cloudflare-logged]
type = "syslog"
resolvers = ["cloudflare-dot"]
network = "udp"
address = "192.168.0.1:514"
priority = "info"
tag = "routedns"
log-request = true
log-response = true
```

Example config files: [syslog.toml](../cmd/routedns/example-config/syslog.toml)

## Resolvers

Resolvers forward queries to other DNS servers over the network and typically represent the end of one or many processing pipelines. Resolvers encode every query that is passed from listeners, modifiers, routers etc and send them to a DNS server without further processing. Like with other elements in the pipeline, resolvers requires a unique identifier to reference them from other elements. The following protocols are supported:

- udp - Plain (un-encrypted) DNS over UDP
- tcp - Plain (un-encrypted) DNS over TCP
- dot - DNS-over-TLS
- doh - DNS-over-HTTP (including DoH over QUIC)
- doq - DNS-over-QUIC

Resolvers are defined in the configuration like so `[resolvers.NAME]` and have the following common options:

- `address` - Remote server endpoint and port. Can be IP or hostname, or a full URL depending on the protocol. See the [Bootstrapping](#Bootstrapping) on how to handle hostnames that can't be resolved.
- `protocol` - The DNS protocol used to send queries, can be `udp`, `tcp`, `dot`, `doh`, `doq`.
- `bootstrap-address` - Use this IP address if the name in `address` can't be resolved. Using the IP in `address` directly may not work when TLS/certificates are used by the server.
- `local-address` - IP of the local interface to use for outgoing connections. The address is automatically chosen if this option is left blank.
- `edns0-udp-size` - If set, modifies the EDNS0 UDP size option in all queries sent upstream. Only meaningful when using UDP or DTLS resolvers. Upstream resolvers may not respect this value and apply their own limits.
- `query-timeout` - Sets the query timeout to allow. In seconds.

Secure resolvers such as DoT, DoH, or DoQ offer additional options to configure the TLS connections.

- `client-crt` - Client certificate file.
- `client-key` - Client certificate key file
- `ca` - CA certificate to validate server certificates.
- `server-name` - Name of the certificate presented by the server if it does not match the name in the endpoint address.

Examples:

A simple DoT resolver.

```toml
[resolvers.cloudflare-dot]
address = "1.1.1.1:853"
protocol = "dot"
```

DoT resolver supporting mutual-TLS, providing a certificate and key, plus validating the remote cert with a CA certificate.

```toml
[resolvers.my-mutual-tls]
address = "myserver:853"
protocol = "dot"
ca = "/path/to/my-ca.pem"
client-key = "/path/to/my-key.pem"
client-crt = "/path/to/my-crt.pem"
```

A list of well-known public DNS services can be found [here](../cmd/routedns/example-config/well-known.toml)

### Bootstrapping

When upstream services are configured using their hostnames, RouteDNS will first have to resolve the hostname of the service before establishing a secure connection with it. There are a couple of potential issues with this:

- The initial lookup is using the OS' resolver which could be using plain/un-encrypted DNS. This may not be desirable or even fail if no other DNS is available.
- The service does not support querying it by IP directly and a hostname is needed. Google for example does not support DoH using `https://8.8.8.8/dns-query`. The endpoint has to be configured as `https://dns.google/dns-query`.

To solve these issues, it is possible to add a bootstrap IP address to the resolver config or to use a [bootstrap resolver](#Bootstrap-Resolver). This will use the IP to connect to the service without first having to perform a lookup while still preserving the DoH URL or DoT hostname for the TLS handshake. The `bootstrap-address` option is available on both, DoT and DoH resolvers.

```toml
[resolvers.google-doh-post-bootstrap]
address = "https://dns.google/dns-query"
protocol = "doh"
bootstrap-address = "8.8.8.8"
```

### Plain DNS Resolver

Plain, un-encrypted DNS protocol clients for UDP or TCP. Use `protocol = "udp"` or `protocol = "tcp"`. Note that UDP responses can be truncated so it is common to use use it in combination with a [truncate-retry](#Retrying-Truncated-Responses) group to define a fallback.

Examples:

```toml
[resolvers.google-udp-8-8-8-8]
address = "8.8.8.8:53"
protocol = "udp"

[resolvers.cloudflare-tcp]
address = "1.1.1.1:53"
protocol = "tcp"
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml), [truncate-retry.toml](../cmd/routedns/example-config/truncate-retry.toml)

### DNS-over-TLS Resolver

DNS protocol using a TLS connection (DoT) as per [RFC7858](https://tools.ietf.org/html/rfc7858). Resolvers are configured with `protocol = "dot"` and additional options such as `client-crt`, `client-key` and `ca` are available.

Examples:

Simple DoT resolver using a well-known service.

```toml
[resolvers.cloudflare-dot-1-1-1-1]
address = "1.1.1.1:853"
protocol = "dot"
```

DoT resolver trusting only a specific CA.

```toml
[resolvers.cloudflare-dot-with-ca]
address = "1.1.1.1:853"
protocol = "dot"
ca = "/path/to/DigiCertECCSecureServerCA.pem"
```

DoT resolver using mTLS with a server that expects a client certificate

```toml
[resolvers.my-mutual-tls]
address = "myserver:853"
protocol = "dot"
ca = "/path/to/my-ca.pem"
client-key = "/path/to/my-key.pem"
client-crt = "/path/to/my-crt.pem"
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml), [family-browsing.toml](../cmd/routedns/example-config/family-browsing.toml), [simple-dot-cache.toml](../cmd/routedns/example-config/simpel-dot-cache.toml)

### DNS-over-HTTPS Resolver

DNS resolvers using the HTTPS protocol are configured with `protocol = "doh"`. By default, DoH uses TCP as transport, but it can also be run over QUIC (UDP) by providing the option `transport = "quic"`. DoH supports two HTTP methods, GET and POST. By default RouteDNS uses the POST method, but can be configured to use GET as well using the option `doh = { method = "GET" }`.
DoH with QUIC supports 0-RTT. The DoH resolver will try to use 0-RTT connection establishment if `transport = "quic"` and `enable-0rtt = true` are configured. When 0-RTT is enabled, the resolver will disregard the configured method and always use GET instead. This means the configured address nees to contain a URL template (with the `{?dns}` part).

Examples:

Simple DoH resolver using the POST method.

```toml
[resolvers.cloudflare-doh-post]
address = "https://1.1.1.1/dns-query"
protocol = "doh"
```

Simple DoH resolver using the GET method.

```toml
[resolvers.cloudflare-doh-get]
address = "https://1.1.1.1/dns-query{?dns}"
protocol = "doh"
doh = { method = "GET" }
```

DoH resolver using QUIC transport.

```toml
[resolvers.cloudflare-doh-quic]
address = "https://cloudflare-dns.com/dns-query{?dns}"
protocol = "doh"
transport = "quic"
enable-0rtt = true
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml), [simple-doh.toml](../cmd/routedns/example-config/simple-doh.toml), [mutual-tls-doh-client.toml](../cmd/routedns/example-config/mutual-tls-doh-client.toml)

### Oblivious DNS (ODoH)

ODoH ([draft](https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh-03)) is intended to improve privacy of **clients** by encrypting queries for a **target** DNS server while sending the query through a **proxy**. In this configuration, neither the target nor the proxy can see the query content and the source IP of the client at the same time. A client query is resolved as follows:

- The client first queries the public key of the target resolver. This is a plain query that can be resolved by any resolver, but for privacy it's best to *not* use the target for this. RouteDNS always uses the proxy for this. The response is validated with DNSSEC.
- The client then encrypts the actual query with the public key of the target. A public key of the client is embedded in the encrypted message.
- The encrypted query message is sent to the proxy, with information about which target it should be forwarded to.
- The target then encrypts the response with the client key and responds to the proxy, which then forwards the response to the client.
- The client decrypts the response it received from the proxy using its private key.

The ODoH resolver has all the configuration options as [DoH](#DNS-over-HTTPS-Resolver), with the configuration (endpoint, certs, mTLS, etc) for the proxy. In addition, a `target` option is available to specify the URL of the target. Configured with `protocol = "odoh"`.

Examples:

ODoH client using Cloudflare as proxy and target (since there aren't any other public proxies as of Dec 2020).

```toml
[resolvers.cloudflare-odoh-proxy]
protocol = "odoh"
# Address of the oblivious DNS proxy server
address = "https://odoh-noads-nl.alekberg.net/proxy"
# Address of the target. The hostname and path are passed to the proxy for forwarding
# of encrypted queries. No cert or bootstrap options for the target since the proxy
# connects to it on the client's behalf
target = "https://odoh.cloudflare-dns.com/dns-query"

# The ODoH config/key of the Target. 
target-config = "0000000secret...."
# The ODoH config is usually hosted on the target under https://[target]/.well-known/odohconfigs 
# If the target-config is not specified here, the resolver will request it automatically. 

```

Example config files: [odoh-client.toml](../cmd/routedns/example-config/odoh-client.toml)

### DNS-over-DTLS Resolver

Similar to DoT, but uses a DTLS (UDP) connection as transport as per [RFC9894](https://tools.ietf.org/html/rfc8094). Configured with `protocol = "dtls"`.

Examples:

DTLS resolver trusting a specific server certificate and setting a bootstrap address to avoid looking up the server IP at startup.

```toml
[resolvers.local-dtls]
address = "server.acme.test:853"
protocol = "dtls"
ca = "example-config/server-ec.crt"
bootstrap-address = "127.0.0.1"
```

Example config files: [dtls-client.toml](../cmd/routedns/example-config/dtls-client.toml)

### DNS-over-QUIC Resolver

Similar to DoT, but uses a QUIC connection as transport as per [RFC9250](https://datatracker.ietf.org/doc/rfc9250/). Configured with `protocol = "doq"`. Note that this is different from DoH over QUIC. See [DNS-over-HTTPS](#DNS-over-HTTPS-Resolver) for how to configure this.
The DoQ resolver will try to use 0-RTT connection establishment if `enable-0rtt = true` is configured.

Examples:

```toml
[resolvers.local-doq]
address = "server.acme.test:8853"
protocol = "doq"
ca = "example-config/server.crt"
bootstrap-address = "127.0.0.1"
enable-0rtt = true
```

Example config files: [doq-client.toml](../cmd/routedns/example-config/doq-client.toml)

### Bootstrap Resolver

Some configuration contain references to external resources by hostname. For example remote blocklists or resolvers. For those configurations to be valid, RouteDNS needs to be able to resolve those names at startup. If RouteDNS is the only service providing name resolution, this would fail. A bootstrap resolver allows the config to provide a resolver that is used to lookup such hostnames from the RouteDNS process itself. Bootstrap resolvers support the same protocols and options as regular resolvers.
Note: Resolvers (including the bootstrap resolver itself) also support a `bootstrap-address` property that sets the IP directly and bypasses the bootstrap resolver.

Examples:

Use Cloudflare DoT to resolve all hostnames in the configuration.

```toml
[bootstrap-resolver]
address = "1.1.1.1:853"
protocol = "dot"
```

Example config files: [bootstrap-resolver.toml](../cmd/routedns/example-config/bootstrap-resolver.toml), [use-case-6.toml](../cmd/routedns/example-config/use-case-6.toml)

### SOCKS5 Proxy Support

Several resolver types support connecting to upstream servers through a SOCKS5 proxy. This includes:

- [Plain DNS](#Plain-DNS-Resolver)
- [DNS-over-TLS](#DNS-over-TLS-Resolver)
- [DNS-over-HTTPS](#DNS-over-HTTPS-Resolver)

If SOCKS5 is available, the following options can be used to configure it:

- `socks5-address` - SOCKS5 server address, including port.
- `socks5-username` - SOCKS5 server username.
- `socks5-password` - SOCKS5 server password.
- `socks5-resolve-local` - Experimental: Resolve the upstream DNS server name locally before connecting through the proxy.

Examples:

```toml
[resolvers.cloudflare-doh]
address = "https://cloudflare-dns.com/dns-query"
protocol = "doh"
socks5-address = "1.2.3.4:1080"
socks5-username = "test"
socks5-password = "test"
```

## Templates

Some groups support templates, i.e. allow placeholder in text fields that will be populated at runtime with data from a query. This can for example be used in the extended error text returned from a blocklist. In that case, the configuration would set a text with placeholders like this `"Blocked {{ .Question }} with ID {{ .ID }} because reasons"`. The placeholders in between `{{` and `}}` would then be replaced with data from the query when a query is blocked and the response returned. The template syntax is explained in more detail [here](https://pkg.go.dev/text/template).

**Data available to templates**

The following pieces of information from the query are available in the template:

- `ID` - The query ID.
- `Question` - The question string.
- `QuestionType` - The question type, `A`, `AAAA`, `CNAME` etc.
- `QuestionClass` - The query class, `IN`, `ANY`, etc.
- `Blocklist` - The name of the blocklist (only present if this request was blocked).
- `BlocklistRule` - The rule on the blocklist that matched (only present if this was blocked).

In addition to the [built-in template functions](https://pkg.go.dev/text/template#hdr-Functions), the following functions are available.

- `replaceAll` - Replace all instances of a substring with another. Equivalent to [strings.ReplaceAll](https://pkg.go.dev/strings#ReplaceAll)
- `trimPrefix` - Removes a prefix from string. Equivalent to [strings.TrimPrefix](https://pkg.go.dev/strings#TrimPrefix).
- `trimSuffix` - Removes a suffix from a string. Equivalent to [strings.TrimSuffix](https://pkg.go.dev/strings#TrimPrefix).
- `split` - Split strings into substrings using the given separator. Equivalent to [strings.Split](https://pkg.go.dev/strings#Split).
- `join` - Concatenates strings with a given separator. Equivalent to [strings.Join](https://pkg.go.dev/strings#Join).

Functions can be combined with conditionals to make more complex template such as this example.

```template
'{{ .Question }} 18000 IN NS {{ if (eq .QuestionType "AAAA") }}ns6{{ else }}ns4{{ end }}.example.com.'
```

Support for additional string-manipulation functions can be added as needed.
