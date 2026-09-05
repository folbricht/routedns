# Example Configurations

Working RouteDNS configurations, one per feature. Each file is a complete config that can be run as-is.

```text
go build -o cmd/routedns/ ./cmd/routedns
cd cmd/routedns
./routedns example-config/simple-dot.toml
```

Some of these reference supporting files by relative path (`./example-config/domains.txt`), so run them from `cmd/routedns/` as shown. Most bind port 53 and need privileges or a port change. To load one without serving queries, use [`--check`](../../../doc/overview.md#validating-a-configuration):

```text
./routedns --check example-config/simple-dot.toml
```

Every option used here is described in the [Configuration Guide](../../../doc/configuration.md), which also indexes every component by the `protocol` or `type` value that selects it. The Guide column below links each example to the section describing the component it demonstrates.

## Start here

| File | Description | Guide |
| --- | --- | --- |
| [simple-dot.toml](simple-dot.toml) | Plain DNS on loopback, forwarded to Cloudflare over DoT. The starting point for most setups. | [DoT resolver](../../../doc/resolvers.md#dns-over-tls-resolver) |
| [simple-doh.toml](simple-doh.toml) | The same, over DoH. | [DoH resolver](../../../doc/resolvers.md#dns-over-https-resolver) |
| [simple-dot-cache.toml](simple-dot-cache.toml) | DoT with a cache in front of the upstream resolver. | [Cache](../../../doc/caching.md#cache) |
| [simple-dot-proxy.toml](simple-dot-proxy.toml) | Network-wide proxy translating plain DNS on port 53 into DoT. | [Plain DNS listener](../../../doc/listeners.md#plain-dns) |
| [use-case-1.toml](use-case-1.toml) | Local proxy with a cache, everything forwarded over DoT. | [Cache](../../../doc/caching.md#cache) |
| [well-known.toml](well-known.toml) | Reference list of public resolvers and the protocols they support. Not meant to be run directly. | [Resolvers](../../../doc/resolvers.md) |
| [well-known-wo-ports.toml](well-known-wo-ports.toml) | The same list relying on each protocol's default port. | [Resolvers](../../../doc/resolvers.md) |
| [restricted-listener.toml](restricted-listener.toml) | Listener that only accepts queries from named client networks (`allowed-net`). | [Listener options](../../../doc/listeners.md#listeners) |

## Protocol clients (resolvers)

| File | Description | Guide |
| --- | --- | --- |
| [dot-client.toml](dot-client.toml) | Forward to a DoT server. | [DoT resolver](../../../doc/resolvers.md#dns-over-tls-resolver) |
| [doq-client.toml](doq-client.toml) | Forward to a local DoQ server, using 0-RTT where possible. | [DoQ resolver](../../../doc/resolvers.md#dns-over-quic-resolver) |
| [doq-client-simple.toml](doq-client-simple.toml) | Forward to a public DoQ server. | [DoQ resolver](../../../doc/resolvers.md#dns-over-quic-resolver) |
| [doh-quic-client.toml](doh-quic-client.toml) | DoH over QUIC transport, with 0-RTT. | [DoH resolver](../../../doc/resolvers.md#dns-over-https-resolver) |
| [doh-quic-client-local.toml](doh-quic-client-local.toml) | DoH over QUIC against the local test server in `doh-quic-server.toml`. | [DoH resolver](../../../doc/resolvers.md#dns-over-https-resolver) |
| [dtls-client.toml](dtls-client.toml) | Forward to a DoDTLS server. | [DTLS resolver](../../../doc/resolvers.md#dns-over-dtls-resolver) |
| [odoh-client.toml](odoh-client.toml) | Oblivious DoH client, with target and optional proxy. | [ODoH resolver](../../../doc/resolvers.md#oblivious-dns-odoh-resolver) |
| [bootstrap-resolver.toml](bootstrap-resolver.toml) | Resolve hostnames used elsewhere in the config (resolver endpoints, blocklist URLs) through a defined resolver. | [Bootstrap resolver](../../../doc/resolvers.md#bootstrap-resolver) |
| [socks5-dot.toml](socks5-dot.toml) | DoT upstream reached through a SOCKS5 proxy. | [SOCKS5](../../../doc/resolvers.md#socks5-proxy-support) |
| [socks5-doh.toml](socks5-doh.toml) | DoH upstream reached through a SOCKS5 proxy. | [SOCKS5](../../../doc/resolvers.md#socks5-proxy-support) |
| [socks5-udp.toml](socks5-udp.toml) | Plain DNS through a SOCKS5 proxy. | [SOCKS5](../../../doc/resolvers.md#socks5-proxy-support) |
| [socks5-udp-resolvelocal.toml](socks5-udp-resolvelocal.toml) | The same, but resolving the server hostname locally rather than on the proxy. | [SOCKS5](../../../doc/resolvers.md#socks5-proxy-support) |

## Protocol servers (listeners)

| File | Description | Guide |
| --- | --- | --- |
| [dot-server.toml](dot-server.toml) | DoT server. | [DoT listener](../../../doc/listeners.md#dns-over-tls) |
| [doq-listener.toml](doq-listener.toml) | DoQ server without mutual TLS. | [DoQ listener](../../../doc/listeners.md#dns-over-quic) |
| [doh-quic-server.toml](doh-quic-server.toml) | DoH server using QUIC transport. | [DoH listener](../../../doc/listeners.md#dns-over-https) |
| [doh-no-tls.toml](doh-no-tls.toml) | DoH server with TLS disabled, for testing or behind a terminating proxy. | [DoH listener](../../../doc/listeners.md#dns-over-https) |
| [doh-behind-proxy.toml](doh-behind-proxy.toml) | DoH server taking the client address from `X-Forwarded-For` sent by a trusted reverse proxy. | [DoH listener](../../../doc/listeners.md#dns-over-https) |
| [dtls-server.toml](dtls-server.toml) | DoDTLS server. | [DTLS listener](../../../doc/listeners.md#dns-over-dtls) |
| [odoh-listener.toml](odoh-listener.toml) | ODoH listener acting as target and proxy. | [ODoH listener](../../../doc/listeners.md#oblivious-dns-odoh) |
| [admin.toml](admin.toml) | Admin listener exposing expvar metrics over HTTPS. | [Admin listener](../../../doc/listeners.md#admin) |

## Mutual TLS

Client and server halves of the same setup, meant to be run as a pair. They reference `/path/to/...` certificates that have to be provided. Documented under the common options in [Listeners](../../../doc/listeners.md#listeners) (`mutual-tls`, `ca`) and [Resolvers](../../../doc/resolvers.md#resolvers) (`client-crt`, `client-key`).

| File | Description |
| --- | --- |
| [mutual-tls-dot-client.toml](mutual-tls-dot-client.toml) / [mutual-tls-dot-server.toml](mutual-tls-dot-server.toml) | DoT with client certificates validated against a private CA. |
| [mutual-tls-doh-client.toml](mutual-tls-doh-client.toml) / [mutual-tls-doh-server.toml](mutual-tls-doh-server.toml) | The same over DoH. |
| [mutual-tls-doq-client.toml](mutual-tls-doq-client.toml) / [mutual-tls-doq-server.toml](mutual-tls-doq-server.toml) | The same over DoH with QUIC transport. |
| [use-case-5-client.toml](use-case-5-client.toml) / [use-case-5-server.toml](use-case-5-server.toml) | Local proxy forwarding over mTLS DoH to a server that resolves over DoT. |

## Caching

| File | Description | Guide |
| --- | --- | --- |
| [cache.toml](cache.toml) | Cache with a size limit, persisted to disk on an interval. | [Cache](../../../doc/caching.md#cache) |
| [cache-flush.toml](cache-flush.toml) | Cache that resets when a defined query name is received. | [Cache](../../../doc/caching.md#cache) |
| [cache-rcode.toml](cache-rcode.toml) | Cache with an upper bound on the TTL of NXDOMAIN responses. | [Cache](../../../doc/caching.md#cache) |
| [cache-redis.toml](cache-redis.toml) | Cache backed by Redis, which allows several instances to share it. | [Cache](../../../doc/caching.md#cache) |
| [cache-with-prefetch.toml](cache-with-prefetch.toml) | Cache refreshing records itself before their TTL runs out. | [Cache](../../../doc/caching.md#cache) |
| [prefetch.toml](prefetch.toml) | Standalone `prefetch` group that tracks frequent queries and refreshes them in a cache upstream of it. | [Prefetch](../../../doc/caching.md#prefetch) |
| [ttl-modifier.toml](ttl-modifier.toml) | Clamp TTLs to a minimum and maximum before caching. | [TTL modifier](../../../doc/caching.md#ttl-modifier) |
| [ttl-modifier-average.toml](ttl-modifier-average.toml) | The same using the `average` selection function. | [TTL modifier](../../../doc/caching.md#ttl-modifier) |
| [request-dedup.toml](request-dedup.toml) | Collapse identical concurrent queries into one upstream query. | [Request dedup](../../../doc/caching.md#request-deduplication) |
| [truncate-retry.toml](truncate-retry.toml) | Query over UDP, retry over TCP when the response is truncated, so only complete responses are cached. | [Truncate-retry](../../../doc/caching.md#retrying-truncated-responses) |
| [fastest-tcp.toml](fastest-tcp.toml) | Probe the response IPs over TCP and cache only the fastest one. | [Fastest TCP](../../../doc/caching.md#fastest-tcp-probe) |

## Blocklists

Query blocklists, matched against the name being asked for. See [Query Blocklist](../../../doc/blocklists.md#query-blocklist).

| File | Description |
| --- | --- |
| [blocklist-domain.toml](blocklist-domain.toml) | `domain` format, covering exact, sub-domain and wildcard rules. |
| [blocklist-domain-subdomain.toml](blocklist-domain-subdomain.toml) | `domain-subdomain` format, where every entry covers the apex and all sub-domains. |
| [blocklist-hosts.toml](blocklist-hosts.toml) | `hosts` format, which can also spoof an address rather than blocking. |
| [blocklist-regexp.toml](blocklist-regexp.toml) | `regexp` format. |
| [blocklist-mac.toml](blocklist-mac.toml) | Match the client MAC address supplied in EDNS0 option 65001. |
| [blocklist-domain-ede.toml](blocklist-domain-ede.toml) | Attach an EDNS0 Extended DNS Error to blocked responses, templated with the rule that matched. |
| [blocklist-local.toml](blocklist-local.toml) | Load a list from a local file and refresh it daily. |
| [blocklist-remote.toml](blocklist-remote.toml) | Load block and allow lists over HTTP and refresh them daily. |
| [blocklist-remote-cache.toml](blocklist-remote-cache.toml) | The same, cached on disk so startup does not wait on the download. |
| [blocklist-allow.toml](blocklist-allow.toml) | Allow-list entries taking precedence over the blocklist. |
| [blocklist-resolver.toml](blocklist-resolver.toml) | Send matching queries to a different resolver instead of answering NXDOMAIN. |
| [block-split-cache.toml](block-split-cache.toml) | Blocklist in front of a router that splits traffic between a cached and an uncached resolver. |

Response blocklists, matched against what came back. See [Response Blocklist](../../../doc/blocklists.md#response-blocklist).

| File | Description |
| --- | --- |
| [response-blocklist-ip.toml](response-blocklist-ip.toml) | Block on the IPs in the answer, by CIDR. |
| [response-blocklist-ip-remote.toml](response-blocklist-ip-remote.toml) | The same with CIDR lists loaded over HTTP. |
| [response-blocklist-ip-resolver.toml](response-blocklist-ip-resolver.toml) | Re-send matching queries to an alternative resolver. |
| [response-blocklist-geo.toml](response-blocklist-geo.toml) | Block by GeoIP location, filtering the matching records out of the response. |
| [response-blocklist-asn.toml](response-blocklist-asn.toml) | Block by the ASN owning the answer IP. Needs a local GeoLite2 ASN database. |
| [response-blocklist-name.toml](response-blocklist-name.toml) | Block on names appearing in the response, such as CNAME targets. |
| [response-blocklist-name-remote.toml](response-blocklist-name-remote.toml) | The same with the list loaded from a file. |
| [response-blocklist-name-resolver.toml](response-blocklist-name-resolver.toml) | Re-send matching queries to an alternative resolver. |

Client blocklists, matched against who asked. See [Client Blocklist](../../../doc/blocklists.md#client-blocklist).

| File | Description |
| --- | --- |
| [client-blocklist.toml](client-blocklist.toml) | Answer REFUSED to clients in given networks. |
| [client-blocklist-refused.toml](client-blocklist-refused.toml) | The same built explicitly with a static responder. |
| [client-blocklist-drop.toml](client-blocklist-drop.toml) | Drop the query without answering. |
| [client-blocklist-geo.toml](client-blocklist-geo.toml) | Refuse clients by GeoIP location. |

## Failover and load balancing

| File | Description | Guide |
| --- | --- | --- |
| [load-balance.toml](load-balance.toml) | Prefer resolvers with lower average response time, retrying elsewhere after a failure. | [Load-balance](../../../doc/groups.md#load-balance-group) |
| [random-resolver.toml](random-resolver.toml) | Pick a resolver at random, taking failing ones out of rotation for a while. | [Random](../../../doc/groups.md#random-group) |
| [fastest.toml](fastest.toml) | Query every resolver at once and use the first good answer. | [Fastest](../../../doc/groups.md#fastest-group) |

## Routing

| File | Description | Guide |
| --- | --- | --- |
| [router.toml](router.toml) | Routes by query type and name, including an inverted route. | [Router](../../../doc/routing.md#router) |
| [router-time.toml](router-time.toml) | Routes by time of day and weekday. | [Router](../../../doc/routing.md#router) |
| [split-dns.toml](split-dns.toml) | Internal names to internal servers, everything else over DoT. | [Router](../../../doc/routing.md#router) |
| [family-browsing.toml](family-browsing.toml) | Per-device filtering by source IP, with a filtered upstream for those devices. | [Router](../../../doc/routing.md#router) |
| [use-case-2.toml](use-case-2.toml) | Corporate split DNS, company servers grouped with fail-rotate, everything else over DoH. | [Router](../../../doc/routing.md#router) |
| [use-case-4.toml](use-case-4.toml) | Multiple VPNs each with their own DNS, rewriting short hostnames to the right domain. | [Router](../../../doc/routing.md#router), [Replace](../../../doc/modifiers.md#replace) |
| [use-case-7.toml](use-case-7.toml) | Per-client policy driven by EDNS Client Subnet when RouteDNS sits behind another resolver. | [ECS source routing](../../../doc/routing.md#ecs-source-routing) |
| [walled-garden.toml](walled-garden.toml) | Route by query type to static responders, so every query gets a canned answer and nothing reaches an upstream resolver. | [Static responder](../../../doc/responders.md#static-responder) |

## Modifiers and responders

| File | Description | Guide |
| --- | --- | --- |
| [ecs-modifier-add.toml](ecs-modifier-add.toml) | Add an EDNS Client Subnet option to outgoing queries. | [ECS modifier](../../../doc/modifiers.md#edns0-client-subnet-modifier) |
| [ecs-modifier-delete.toml](ecs-modifier-delete.toml) | Strip ECS from outgoing queries. | [ECS modifier](../../../doc/modifiers.md#edns0-client-subnet-modifier) |
| [ecs-modifier-privacy.toml](ecs-modifier-privacy.toml) | Truncate ECS to a coarser prefix instead of removing it. | [ECS modifier](../../../doc/modifiers.md#edns0-client-subnet-modifier) |
| [edns0-modifier.toml](edns0-modifier.toml) | Add an arbitrary EDNS0 option, here a MAC address for OpenDNS. | [EDNS0 modifier](../../../doc/modifiers.md#edns0-modifier) |
| [response-minimize.toml](response-minimize.toml) | Strip Extra and NS records from responses. | [Response minimizer](../../../doc/modifiers.md#response-minimizer) |
| [response-collapse.toml](response-collapse.toml) | Collapse CNAME chains in the answer. | [Response collapse](../../../doc/modifiers.md#response-collapse) |
| [static-extended-error.toml](static-extended-error.toml) | Static response carrying an Extended DNS Error explaining the block. | [Static responder](../../../doc/responders.md#static-responder) |
| [static-template.toml](static-template.toml) | Build the response from the query with a Go template. | [Static template](../../../doc/responders.md#static-template-responder) |
| [static-template-error.toml](static-template-error.toml) | The same, returning an error response. | [Static template](../../../doc/responders.md#static-template-responder) |
| [rfc8482.toml](rfc8482.toml) | Answer ANY queries with an HINFO record as per RFC 8482. | [Static responder](../../../doc/responders.md#static-responder) |
| [truncate.toml](truncate.toml) | Set the TC bit on UDP responses to push clients onto TCP. | [Static responder](../../../doc/responders.md#static-responder) |
| [rate-limiter.toml](rate-limiter.toml) | Limit the query rate per client subnet. | [Rate limiter](../../../doc/security.md#rate-limiter) |

## DNSSEC

See [DNSSEC Validator](../../../doc/security.md#dnssec-validator).

| File | Description |
| --- | --- |
| [dnssec-validator.toml](dnssec-validator.toml) | Validate responses using the built-in IANA root trust anchor. |
| [dnssec-validator-iana.toml](dnssec-validator-iana.toml) | Load the root anchor from the IANA XML at startup instead of using the built-in one. |
| [dnssec-validator-trust-anchors.toml](dnssec-validator-trust-anchors.toml) | Explicit trust anchors, with log-only mode. |

## Lua

See [Lua Scripting](../../../doc/scripting.md#lua) and the [Lua API](../../../doc/scripting.md#lua-api).

| File | Description |
| --- | --- |
| [lua-passthrough.toml](lua-passthrough.toml) | Minimal script that forwards queries unchanged. The skeleton to start from. |
| [lua-static-answer.toml](lua-static-answer.toml) | Answer one name from the script, forward the rest. |
| [lua-routing.toml](lua-routing.toml) | Choose an upstream resolver by matching the query name. |
| [lua-opt.toml](lua-opt.toml) | Answer NXDOMAIN with an Extended DNS Error attached. |
| [lua-version.toml](lua-version.toml) | Answer `version.routedns.` CH TXT with the running version, like `version.bind`. |
| [lua-any-emulator.toml](lua-any-emulator.toml) | Emulate ANY by querying common types individually and merging the answers. |

## Logging and metrics

| File | Description | Guide |
| --- | --- | --- |
| [query-log.toml](query-log.toml) | Log queries and responses in text or JSON. | [Query log](../../../doc/observability.md#query-log) |
| [syslog.toml](syslog.toml) | Send query logs to syslog. | [Syslog](../../../doc/observability.md#syslog) |
| [admin.toml](admin.toml) | expvar metrics over HTTPS. | [Admin listener](../../../doc/listeners.md#admin) |
| [prometheus-exporter/](prometheus-exporter/) | The admin listener paired with prometheus-expvar-exporter. | [Admin listener](../../../doc/listeners.md#admin) |

## Linux networking

| File | Description | Guide |
| --- | --- | --- |
| [netns.toml](netns.toml) | Listen in one network namespace and resolve in another. Needs `CAP_SYS_ADMIN`. | [Network namespaces](../../../doc/resolvers.md#network-namespace-support) |
| [xsocket.toml](xsocket.toml) | The same through an xsocket server, without `CAP_SYS_ADMIN`. | [xsocket](../../../doc/resolvers.md#without-elevated-privileges-xsocket) |
| [fwmark-bind-if.toml](fwmark-bind-if.toml) | `SO_MARK` and `SO_BINDTODEVICE` for policy routing and multi-WAN. | [fwmark, bind-if](../../../doc/resolvers.md#firewall-mark-and-interface-binding) |

## Whole-network setups

| File | Description | Guide |
| --- | --- | --- |
| [use-case-6.toml](use-case-6.toml) | Home network resolver: caching, TTL clamping, and query, response-name and response-IP blocklists refreshed daily. | [Blocklists](../../../doc/blocklists.md) |
| [split-config/](split-config/) | One configuration broken across several files, loaded together. | [Split configuration](../../../doc/overview.md#split-configuration) |

## Supporting files

| File | Description | Guide |
| --- | --- | --- |
| [domains.txt](domains.txt) | Domain blocklist used by the file-based examples. | [Query blocklist](../../../doc/blocklists.md#query-blocklist) |
| [cidr.txt](cidr.txt) | CIDR list for response IP blocklists. | [Response blocklist](../../../doc/blocklists.md#response-blocklist) |
| [location.txt](location.txt) | GeoIP location list, with the ID format the geo blocklists expect. | [Response blocklist](../../../doc/blocklists.md#response-blocklist) |
| `server.crt`, `server.key` | Self-signed certificate for the TLS listener examples. | [Listener TLS options](../../../doc/listeners.md#listeners) |
| `server-ec.crt`, `server-ec.key` | The same with an EC key. | [Listener TLS options](../../../doc/listeners.md#listeners) |
