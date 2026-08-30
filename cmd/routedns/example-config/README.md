# Example Configurations

Working RouteDNS configurations, one per feature. Each file is a complete config that can be run as-is.

```text
go build -o cmd/routedns/ ./cmd/routedns
cd cmd/routedns
./routedns example-config/simple-dot.toml
```

Some of these reference supporting files by relative path (`./example-config/domains.txt`), so run them from `cmd/routedns/` as shown. Most bind port 53 and need privileges or a port change. To load one without serving queries, use [`--check`](../../../doc/configuration.md#validating-a-configuration):

```text
./routedns --check example-config/simple-dot.toml
```

Every option used here is described in the [Configuration Guide](../../../doc/configuration.md).

## Start here

| File | Description |
| --- | --- |
| [simple-dot.toml](simple-dot.toml) | Plain DNS on loopback, forwarded to Cloudflare over DoT. The starting point for most setups. |
| [simple-doh.toml](simple-doh.toml) | The same, over DoH. |
| [simple-dot-cache.toml](simple-dot-cache.toml) | DoT with a cache in front of the upstream resolver. |
| [simple-dot-proxy.toml](simple-dot-proxy.toml) | Network-wide proxy translating plain DNS on port 53 into DoT. |
| [use-case-1.toml](use-case-1.toml) | Local proxy with a cache, everything forwarded over DoT. |
| [well-known.toml](well-known.toml) | Reference list of public resolvers and the protocols they support. Not meant to be run directly. |
| [well-known-wo-ports.toml](well-known-wo-ports.toml) | The same list relying on each protocol's default port. |
| [restricted-listener.toml](restricted-listener.toml) | Listener that only accepts queries from named client networks (`allowed-net`). |

## Protocol clients (resolvers)

| File | Description |
| --- | --- |
| [dot-client.toml](dot-client.toml) | Forward to a DoT server. |
| [doq-client.toml](doq-client.toml) | Forward to a local DoQ server, using 0-RTT where possible. |
| [doq-client-simple.toml](doq-client-simple.toml) | Forward to a public DoQ server. |
| [doh-quic-client.toml](doh-quic-client.toml) | DoH over QUIC transport, with 0-RTT. |
| [doh-quic-client-local.toml](doh-quic-client-local.toml) | DoH over QUIC against the local test server in `doh-quic-server.toml`. |
| [dtls-client.toml](dtls-client.toml) | Forward to a DoDTLS server. |
| [odoh-client.toml](odoh-client.toml) | Oblivious DoH client, with target and optional proxy. |
| [bootstrap-resolver.toml](bootstrap-resolver.toml) | Resolve hostnames used elsewhere in the config (resolver endpoints, blocklist URLs) through a defined resolver. |
| [socks5-dot.toml](socks5-dot.toml) | DoT upstream reached through a SOCKS5 proxy. |
| [socks5-doh.toml](socks5-doh.toml) | DoH upstream reached through a SOCKS5 proxy. |
| [socks5-udp.toml](socks5-udp.toml) | Plain DNS through a SOCKS5 proxy. |
| [socks5-udp-resolvelocal.toml](socks5-udp-resolvelocal.toml) | The same, but resolving the server hostname locally rather than on the proxy. |

## Protocol servers (listeners)

| File | Description |
| --- | --- |
| [dot-server.toml](dot-server.toml) | DoT server. |
| [doq-listener.toml](doq-listener.toml) | DoQ server without mutual TLS. |
| [doh-quic-server.toml](doh-quic-server.toml) | DoH server using QUIC transport. |
| [doh-no-tls.toml](doh-no-tls.toml) | DoH server with TLS disabled, for testing or behind a terminating proxy. |
| [doh-behind-proxy.toml](doh-behind-proxy.toml) | DoH server taking the client address from `X-Forwarded-For` sent by a trusted reverse proxy. |
| [dtls-server.toml](dtls-server.toml) | DoDTLS server. |
| [odoh-listener.toml](odoh-listener.toml) | ODoH listener acting as target and proxy. |
| [admin.toml](admin.toml) | Admin listener exposing expvar metrics over HTTPS. |

## Mutual TLS

Client and server halves of the same setup, meant to be run as a pair. They reference `/path/to/...` certificates that have to be provided.

| File | Description |
| --- | --- |
| [mutual-tls-dot-client.toml](mutual-tls-dot-client.toml) / [mutual-tls-dot-server.toml](mutual-tls-dot-server.toml) | DoT with client certificates validated against a private CA. |
| [mutual-tls-doh-client.toml](mutual-tls-doh-client.toml) / [mutual-tls-doh-server.toml](mutual-tls-doh-server.toml) | The same over DoH. |
| [mutual-tls-doq-client.toml](mutual-tls-doq-client.toml) / [mutual-tls-doq-server.toml](mutual-tls-doq-server.toml) | The same over DoH with QUIC transport. |
| [use-case-5-client.toml](use-case-5-client.toml) / [use-case-5-server.toml](use-case-5-server.toml) | Local proxy forwarding over mTLS DoH to a server that resolves over DoT. |

## Caching

| File | Description |
| --- | --- |
| [cache.toml](cache.toml) | Cache with a size limit, persisted to disk on an interval. |
| [cache-flush.toml](cache-flush.toml) | Cache that resets when a defined query name is received. |
| [cache-rcode.toml](cache-rcode.toml) | Cache with an upper bound on the TTL of NXDOMAIN responses. |
| [cache-redis.toml](cache-redis.toml) | Cache backed by Redis, which allows several instances to share it. |
| [cache-with-prefetch.toml](cache-with-prefetch.toml) | Cache refreshing records itself before their TTL runs out. |
| [prefetch.toml](prefetch.toml) | Standalone `prefetch` group that tracks frequent queries and refreshes them in a cache upstream of it. |
| [ttl-modifier.toml](ttl-modifier.toml) | Clamp TTLs to a minimum and maximum before caching. |
| [ttl-modifier-average.toml](ttl-modifier-average.toml) | The same using the `average` selection function. |
| [request-dedup.toml](request-dedup.toml) | Collapse identical concurrent queries into one upstream query. |
| [truncate-retry.toml](truncate-retry.toml) | Query over UDP, retry over TCP when the response is truncated, so only complete responses are cached. |
| [fastest-tcp.toml](fastest-tcp.toml) | Probe the response IPs over TCP and cache only the fastest one. |

## Blocklists

Query blocklists, matched against the name being asked for.

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

Response blocklists, matched against what came back.

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

Client blocklists, matched against who asked.

| File | Description |
| --- | --- |
| [client-blocklist.toml](client-blocklist.toml) | Answer REFUSED to clients in given networks. |
| [client-blocklist-refused.toml](client-blocklist-refused.toml) | The same built explicitly with a static responder. |
| [client-blocklist-drop.toml](client-blocklist-drop.toml) | Drop the query without answering. |
| [client-blocklist-geo.toml](client-blocklist-geo.toml) | Refuse clients by GeoIP location. |

## Failover and load balancing

| File | Description |
| --- | --- |
| [load-balance.toml](load-balance.toml) | Prefer resolvers with lower average response time, retrying elsewhere after a failure. |
| [random-resolver.toml](random-resolver.toml) | Pick a resolver at random, taking failing ones out of rotation for a while. |
| [fastest.toml](fastest.toml) | Query every resolver at once and use the first good answer. |

## Routing

| File | Description |
| --- | --- |
| [router.toml](router.toml) | Routes by query type and name, including an inverted route. |
| [router-time.toml](router-time.toml) | Routes by time of day and weekday. |
| [split-dns.toml](split-dns.toml) | Internal names to internal servers, everything else over DoT. |
| [family-browsing.toml](family-browsing.toml) | Per-device filtering by source IP, with a filtered upstream for those devices. |
| [use-case-2.toml](use-case-2.toml) | Corporate split DNS, company servers grouped with fail-rotate, everything else over DoH. |
| [use-case-4.toml](use-case-4.toml) | Multiple VPNs each with their own DNS, rewriting short hostnames to the right domain. |
| [use-case-7.toml](use-case-7.toml) | Per-client policy driven by EDNS Client Subnet when RouteDNS sits behind another resolver. |
| [walled-garden.toml](walled-garden.toml) | Route by query type to static responders, so every query gets a canned answer and nothing reaches an upstream resolver. |

## Modifiers and responders

| File | Description |
| --- | --- |
| [ecs-modifier-add.toml](ecs-modifier-add.toml) | Add an EDNS Client Subnet option to outgoing queries. |
| [ecs-modifier-delete.toml](ecs-modifier-delete.toml) | Strip ECS from outgoing queries. |
| [ecs-modifier-privacy.toml](ecs-modifier-privacy.toml) | Truncate ECS to a coarser prefix instead of removing it. |
| [edns0-modifier.toml](edns0-modifier.toml) | Add an arbitrary EDNS0 option, here a MAC address for OpenDNS. |
| [response-minimize.toml](response-minimize.toml) | Strip Extra and NS records from responses. |
| [response-collapse.toml](response-collapse.toml) | Collapse CNAME chains in the answer. |
| [static-extended-error.toml](static-extended-error.toml) | Static response carrying an Extended DNS Error explaining the block. |
| [static-template.toml](static-template.toml) | Build the response from the query with a Go template. |
| [static-template-error.toml](static-template-error.toml) | The same, returning an error response. |
| [rfc8482.toml](rfc8482.toml) | Answer ANY queries with an HINFO record as per RFC 8482. |
| [truncate.toml](truncate.toml) | Set the TC bit on UDP responses to push clients onto TCP. |
| [rate-limiter.toml](rate-limiter.toml) | Limit the query rate per client subnet. |

## DNSSEC

| File | Description |
| --- | --- |
| [dnssec-validator.toml](dnssec-validator.toml) | Validate responses using the built-in IANA root trust anchor. |
| [dnssec-validator-iana.toml](dnssec-validator-iana.toml) | Load the root anchor from the IANA XML at startup instead of using the built-in one. |
| [dnssec-validator-trust-anchors.toml](dnssec-validator-trust-anchors.toml) | Explicit trust anchors, with log-only mode. |

## Lua

| File | Description |
| --- | --- |
| [lua-passthrough.toml](lua-passthrough.toml) | Minimal script that forwards queries unchanged. The skeleton to start from. |
| [lua-static-answer.toml](lua-static-answer.toml) | Answer one name from the script, forward the rest. |
| [lua-routing.toml](lua-routing.toml) | Choose an upstream resolver by matching the query name. |
| [lua-opt.toml](lua-opt.toml) | Answer NXDOMAIN with an Extended DNS Error attached. |
| [lua-version.toml](lua-version.toml) | Answer `version.routedns.` CH TXT with the running version, like `version.bind`. |
| [lua-any-emulator.toml](lua-any-emulator.toml) | Emulate ANY by querying common types individually and merging the answers. |

## Logging and metrics

| File | Description |
| --- | --- |
| [query-log.toml](query-log.toml) | Log queries and responses in text or JSON. |
| [syslog.toml](syslog.toml) | Send query logs to syslog. |
| [admin.toml](admin.toml) | expvar metrics over HTTPS. |
| [prometheus-exporter/](prometheus-exporter/) | The admin listener paired with prometheus-expvar-exporter. |

## Linux networking

| File | Description |
| --- | --- |
| [netns.toml](netns.toml) | Listen in one network namespace and resolve in another. Needs `CAP_SYS_ADMIN`. |
| [xsocket.toml](xsocket.toml) | The same through an xsocket server, without `CAP_SYS_ADMIN`. |
| [fwmark-bind-if.toml](fwmark-bind-if.toml) | `SO_MARK` and `SO_BINDTODEVICE` for policy routing and multi-WAN. |

## Whole-network setups

| File | Description |
| --- | --- |
| [use-case-6.toml](use-case-6.toml) | Home network resolver: caching, TTL clamping, and query, response-name and response-IP blocklists refreshed daily. |
| [split-config/](split-config/) | One configuration broken across several files, loaded together. |

## Supporting files

| File | Description |
| --- | --- |
| [domains.txt](domains.txt) | Domain blocklist used by the file-based examples. |
| [cidr.txt](cidr.txt) | CIDR list for response IP blocklists. |
| [location.txt](location.txt) | GeoIP location list, with the ID format the geo blocklists expect. |
| `server.crt`, `server.key` | Self-signed certificate for the TLS listener examples. |
| `server-ec.crt`, `server-ec.key` | The same with an EC key. |
