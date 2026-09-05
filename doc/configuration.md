# RouteDNS Configuration Guide

An index of everything that can appear in a configuration file. Each component is listed under the value used to select it in TOML, `protocol` for listeners and resolvers, `type` for everything in between.

New to RouteDNS? Start with the [Overview](overview.md), then look up the pieces here. Every component also has a working example under [example-config](../cmd/routedns/example-config/).

[Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | [Responders](responders.md) | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | [Templates](templates.md)

## How a configuration is structured

A configuration is a [TOML](https://github.com/toml-lang/toml) file with four kinds of sections. Each element gets a unique name, and elements reference each other by name to form a pipeline that runs from a listener, through any number of routers, groups and modifiers, to a resolver.

```toml
[listeners.NAME]   # receives queries from clients      -> protocol = "udp" | "dot" | ...
[routers.NAME]     # splits the pipeline by query       -> routes = [...]
[groups.NAME]      # everything in between              -> type = "cache" | "blocklist-v2" | ...
[resolvers.NAME]   # sends queries upstream             -> protocol = "udp" | "doh" | ...
```

Sections can appear in any order, and a single file can hold several independent pipelines. See the [Overview](overview.md) for a complete example, [split configurations](overview.md#split-configuration), and [validating a config](overview.md#validating-a-configuration) with `--check`.

## Listeners

Query receivers, the start of a pipeline. Defined as `[listeners.NAME]` and selected with `protocol`. Options common to all listeners, including TLS, `allowed-net` and the Linux socket options, are described at the top of the [Listeners](listeners.md) page.

| `protocol` | Listener | Description |
| --- | --- | --- |
| `udp` | [Plain DNS](listeners.md#plain-dns) | Un-encrypted DNS over UDP. |
| `tcp` | [Plain DNS](listeners.md#plain-dns) | Un-encrypted DNS over TCP. |
| `dot` | [DNS-over-TLS](listeners.md#dns-over-tls) | DoT server, [RFC 7858](https://tools.ietf.org/html/rfc7858). |
| `doh` | [DNS-over-HTTPS](listeners.md#dns-over-https) | DoH server, [RFC 8484](https://tools.ietf.org/html/rfc8484), over HTTP/2 or QUIC. |
| `doq` | [DNS-over-QUIC](listeners.md#dns-over-quic) | DoQ server, [RFC 9250](https://datatracker.ietf.org/doc/rfc9250/). |
| `dtls` | [DNS-over-DTLS](listeners.md#dns-over-dtls) | DTLS server, [RFC 8094](https://tools.ietf.org/html/rfc8094). |
| `odoh` | [Oblivious DNS](listeners.md#oblivious-dns-odoh) | ODoH target and/or proxy, [RFC 9230](https://datatracker.ietf.org/doc/rfc9230/). |
| `admin` | [Admin](listeners.md#admin) | Metrics endpoint in [expvar](https://pkg.go.dev/expvar) format, not a DNS listener. |

## Routers

Routers split a pipeline into multiple paths. Defined as `[routers.NAME]` with a list of routes, they have no `type`.

| Component | Description |
| --- | --- |
| [Router](routing.md#router) | Direct queries to different elements by query name, type, class, client IP, ECS subnet or time of day. Routes are evaluated [in order](routing.md#route-evaluation-order), first match wins. |
| [ECS source routing](routing.md#ecs-source-routing) | Route on the address in the EDNS0 Client Subnet option rather than the connection source. |

## Groups, modifiers and responders

Everything between a listener and a resolver. All are defined as `[groups.NAME]` and selected with `type`, regardless of what they do.

| `type` | Description | Documented in |
| --- | --- | --- |
| `blocklist-v2` | Block or reroute queries by name, using domain, regexp, hosts-file or MAC rules from config, disk or HTTP. | [Blocklists](blocklists.md#query-blocklist) |
| `cache` | Cache responses in memory or Redis, with optional prefetch and persistence across restarts. | [Caching](caching.md#cache) |
| `client-blocklist` | Block or reroute queries by client IP, CIDR or geographical location. | [Blocklists](blocklists.md#client-blocklist) |
| `dns64` | Synthesize AAAA records from A records for IPv6-only clients behind NAT64. | [Modifiers](modifiers.md#dns64) |
| `dnssec-validator` | Validate DNSSEC signatures against root trust anchors, SERVFAIL on failure. | [Security](security.md#dnssec-validator) |
| `drop` | Terminate a pipeline by dropping the query without replying. | [Responders](responders.md#drop) |
| `ecs-modifier` | Add, replace, delete or truncate the EDNS0 Client Subnet option. | [Modifiers](modifiers.md#edns0-client-subnet-modifier) |
| `edns0-modifier` | Add or remove arbitrary EDNS0 options in queries. | [Modifiers](modifiers.md#edns0-modifier) |
| `fail-back` | Failover that returns to the preferred resolver once it recovers. | [Failover](groups.md#fail-back-group) |
| `fail-rotate` | Failover to the next resolver on error, staying there until it too fails. | [Failover](groups.md#fail-rotate-group) |
| `fastest` | Send every query to all resolvers, use the fastest successful response. | [Failover](groups.md#fastest-group) |
| `fastest-tcp` | TCP-probe the A/AAAA records in a response and answer with the fastest address. | [Caching](caching.md#fastest-tcp-probe) |
| `load-balance` | Weighted random distribution across all resolvers, based on measured response time. | [Failover](groups.md#load-balance-group) |
| `lua` | Custom query handling logic in a sandboxed Lua script. | [Scripting](scripting.md#lua) |
| `prefetch` | Track frequently queried records and refresh them before they expire. | [Caching](caching.md#prefetch) |
| `query-log` | Log query details to a file or STDOUT. | [Logging](observability.md#query-log) |
| `random` | Pick a resolver at random, deactivating failed ones for a time. | [Failover](groups.md#random-group) |
| `rate-limiter` | Limit how many queries a client or network can make per time window. | [Security](security.md#rate-limiter) |
| `replace` | Rewrite query names with regular expressions, mapping responses back. | [Modifiers](modifiers.md#replace) |
| `request-dedup` | Collapse identical concurrent queries into a single upstream query. | [Caching](caching.md#request-deduplication) |
| `response-blocklist-ip` | Block responses by IP, CIDR, geographical location or ASN. | [Blocklists](blocklists.md#response-blocklist) |
| `response-blocklist-name` | Block responses by name in CNAME, MX, NS, PTR and SRV records. | [Blocklists](blocklists.md#response-blocklist) |
| `response-collapse` | Collapse CNAME chains in the answer to the queried name and type. | [Modifiers](modifiers.md#response-collapse) |
| `response-minimize` | Strip Extra and NS records from responses. | [Modifiers](modifiers.md#response-minimizer) |
| `round-robin` | Send each query to the next resolver in the list. | [Failover](groups.md#round-robin-group) |
| `static-responder` | Answer every query with a fixed set of records and RCode. | [Responders](responders.md#static-responder) |
| `static-template` | Answer with records built from [templates](templates.md) using data from the query. | [Responders](responders.md#static-template-responder) |
| `syslog` | Log queries and responses to a local or remote syslog server. | [Logging](observability.md#syslog) |
| `truncate-retry` | Retry truncated responses with a second resolver, typically over TCP. | [Caching](caching.md#retrying-truncated-responses) |
| `ttl-modifier` | Clamp response TTLs to a minimum and maximum. | [Caching](caching.md#ttl-modifier) |

Two older names still work but should not be used in new configurations: `response-blocklist-cidr` is the former name of `response-blocklist-ip`, and `blocklist` is the first-generation query blocklist superseded by `blocklist-v2`.

## Resolvers

Query senders, the end of a pipeline. Defined as `[resolvers.NAME]` and selected with `protocol`. Options common to all resolvers, including TLS, local addresses and the Linux socket options, are described at the top of the [Resolvers](resolvers.md) page.

| `protocol` | Resolver | Description |
| --- | --- | --- |
| `udp` | [Plain DNS](resolvers.md#plain-dns-resolver) | Un-encrypted DNS over UDP. |
| `tcp` | [Plain DNS](resolvers.md#plain-dns-resolver) | Un-encrypted DNS over TCP. |
| `dot` | [DNS-over-TLS](resolvers.md#dns-over-tls-resolver) | DoT client, [RFC 7858](https://tools.ietf.org/html/rfc7858). |
| `doh` | [DNS-over-HTTPS](resolvers.md#dns-over-https-resolver) | DoH client, [RFC 8484](https://tools.ietf.org/html/rfc8484), over HTTP/2 or QUIC. |
| `doq` | [DNS-over-QUIC](resolvers.md#dns-over-quic-resolver) | DoQ client, [RFC 9250](https://datatracker.ietf.org/doc/rfc9250/). |
| `dtls` | [DNS-over-DTLS](resolvers.md#dns-over-dtls-resolver) | DTLS client, [RFC 8094](https://tools.ietf.org/html/rfc8094). |
| `odoh` | [Oblivious DNS](resolvers.md#oblivious-dns-odoh-resolver) | ODoH client, [RFC 9230](https://datatracker.ietf.org/doc/rfc9230/). |

Resolver behaviour that is not a protocol of its own:

| Topic | Description |
| --- | --- |
| [Bootstrapping](resolvers.md#bootstrapping) | Reach a service by IP while keeping its hostname for the TLS handshake, with `bootstrap-address` or a [bootstrap resolver](resolvers.md#bootstrap-resolver). |
| [SOCKS5 proxy](resolvers.md#socks5-proxy-support) | Send upstream connections through a SOCKS5 proxy. |
| [Network namespaces](resolvers.md#network-namespace-support) | Listen in one Linux netns and resolve in another, with `netns` or [xsocket](resolvers.md#without-elevated-privileges-xsocket). |
| [fwmark and interface binding](resolvers.md#firewall-mark-and-interface-binding) | `SO_MARK` and `SO_BINDTODEVICE` for policy routing and VRFs. |

## Pages

| Page | Covers |
| --- | --- |
| [Overview](overview.md) | File format, pipeline model, split configurations, `--check`, writable paths. |
| [Listeners](listeners.md) | All listener protocols and the options common to them. |
| [Routing](routing.md) | Routers, route matching and evaluation order, ECS source routing. |
| [Blocklists](blocklists.md) | Query, response and client blocklists, rule formats and sources. |
| [Caching and Performance](caching.md) | Cache, prefetch, TTL modifier, TCP probing, truncate-retry, deduplication. |
| [Failover and Load Balancing](groups.md) | Round-robin, fail-rotate, fail-back, random, load-balance, fastest. |
| [Modifiers](modifiers.md) | Name replacement, EDNS0 and ECS manipulation, response trimming, DNS64. |
| [Responders](responders.md) | Static and templated answers, dropping queries. |
| [Lua Scripting](scripting.md) | Lua groups, the sandbox, and the exposed API. |
| [DNSSEC and Rate Limiting](security.md) | DNSSEC validation and per-client rate limits. |
| [Logging](observability.md) | Syslog and query logging. |
| [Resolvers](resolvers.md) | All resolver protocols, bootstrapping, proxies and Linux socket options. |
| [Templates](templates.md) | Placeholder syntax for options that take templated text. |
