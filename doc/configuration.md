# RouteDNS Configuration Guide

The guide is split by topic. Every section below links to the page that now holds it; the anchors on this page are unchanged, so existing links into the guide still work.

[Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | [Responders](responders.md) | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | [Templates](templates.md)

## Overview

RouteDNS uses a config file in [TOML](https://github.com/toml-lang/toml) format which is passed to the tool as argument on the command line. See **[Overview](overview.md)**.

### Split Configuration

Configuration can be broken up into individual files to support large or generated configurations.

-> [Overview](overview.md#split-configuration)

### Validating a Configuration

The `--check` option loads a configuration, builds everything it defines, and exits without serving any queries.

-> [Overview](overview.md#validating-a-configuration)

### Writable Paths

Three options write to disk: the cache `filename`, the blocklist `cache-dir`, and the query log `output-file`.

-> [Overview](overview.md#writable-paths)

## Listeners

Listeners are query receivers that form the start of a query pipeline. See **[Listeners](listeners.md)**.

### Plain DNS

Regular (insecure) DNS protocol over port 53, UDP and TCP.

-> [Listeners](listeners.md#plain-dns)

### DNS-over-TLS

DNS protocol using a TLS connection (DoT) as per [RFC7858](https://tools.ietf.org/html/rfc7858).

-> [Listeners](listeners.md#dns-over-tls)

### DNS-over-HTTPS

DNS using the HTTPS protocol as per [RFC8484](https://tools.ietf.org/html/rfc8484).

-> [Listeners](listeners.md#dns-over-https)

### Oblivious DNS (ODoH)

ODoH ([RFC9230](https://datatracker.ietf.org/doc/rfc9230/)) improves the privacy of **clients** by encrypting queries for a **target** DNS server and sending them through a **proxy**, so that neither the target nor the proxy sees the query content and the source IP of the client at the same time.

-> [Listeners](listeners.md#oblivious-dns-odoh)

### DNS-over-DTLS

Similar to DoT, but uses a DTLS (UDP) connection as transport as per [RFC8094](https://tools.ietf.org/html/rfc8094).

-> [Listeners](listeners.md#dns-over-dtls)

### DNS-over-QUIC

Similar to DoT, but uses a QUIC connection as transport as per [RFC9250](https://datatracker.ietf.org/doc/rfc9250/).

-> [Listeners](listeners.md#dns-over-quic)

### Admin

The Admin listener provides metrics on RouteDNS usage and performance at https://{address}/routedns/vars/ in [expvar](https://pkg.go.dev/expvar) format.

-> [Listeners](listeners.md#admin)

## Modifiers, Groups and Routers

The processing pipeline: everything between a listener and a resolver. Split across several pages by what the component does.

### Cache

A cache will store the responses to queries in memory and respond to further identical queries with the same response.

-> [Caching and Performance](caching.md#cache)

### Prefetch

While [Cache](#cache) has built-in prefetch capabilities, the dedicated `prefetch` group may be more appropriate for some use cases.

-> [Caching and Performance](caching.md#prefetch)

### TTL modifier

A TTL modifier is used to adjust the time-to-live (TTL) of DNS responses.

-> [Caching and Performance](caching.md#ttl-modifier)

### Round-Robin group

A Round-Robin balancer groups multiple upstream resolvers and sends every received query to the next resolver.

-> [Failover and Load Balancing](groups.md#round-robin-group)

### Fail-Rotate group

In a Fail-Rotate group, one of the upstream resolvers or modifiers is active and receives all queries.

-> [Failover and Load Balancing](groups.md#fail-rotate-group)

### Fail-Back group

Similar to [fail-rotate](#fail-rotate-group) but will attempt to fall back to the original order (prioritizing the first) if there are no failures for a minute.

-> [Failover and Load Balancing](groups.md#fail-back-group)

### Random group

This group will pick a resolver from its list of upstream resolvers at random.

-> [Failover and Load Balancing](groups.md#random-group)

### Load-Balance group

This group distributes queries across all configured resolvers using weighted random selection based on measured response times.

-> [Failover and Load Balancing](groups.md#load-balance-group)

### Fastest group

This group will send every query to all configured resolvers but only use the fastest (successful) response.

-> [Failover and Load Balancing](groups.md#fastest-group)

### Replace

The replace modifier applies regular expressions to query strings and replaces them before forwarding the query to the upstream resolver or modifier.

-> [Modifiers](modifiers.md#replace)

### Query Blocklist

Query blocklists can be added to resolver-chains to prevent further processing of queries (return NXDOMAIN or spoofed IP) or to send queries to different resolvers if the query name matches a rule on the blocklist.

-> [Blocklists](blocklists.md#query-blocklist)

### Response Blocklist

Rather than filtering queries, response blocklists evaluate the response to a query and block anything that matches a filter-rule.

-> [Blocklists](blocklists.md#response-blocklist)

### Client Blocklist

Client blocklists match the IP of the client instead of responses.

-> [Blocklists](blocklists.md#client-blocklist)

### EDNS0 Client Subnet Modifier

A client subnet modifier is used to either remove ECS options from a query, replace/add one, or improve privacy by hiding more bits of the address.

-> [Modifiers](modifiers.md#edns0-client-subnet-modifier)

### EDNS0 Modifier

EDNS0 Modifier allows low-level operations on the EDNS0 option records in queries.

-> [Modifiers](modifiers.md#edns0-modifier)

### Static responder

A static responder can be used to terminate every query made to it with a fixed answer.

-> [Responders](responders.md#static-responder)

### Static Template Responder

A static template responder operates similarly to a [Static Responder](#static-responder) with the main difference being that the records configured are templates, meaning they can contain placeholders which can refer to data in the query, such as the question.

-> [Responders](responders.md#static-template-responder)

### Drop

Terminates a pipeline by dropping the request.

-> [Responders](responders.md#drop)

### Response Minimizer

This element passes all queries to its upstream resolver and strips all Extra and NS records from the response, making responses smaller.

-> [Modifiers](modifiers.md#response-minimizer)

### Response Collapse

This element passes all queries to its upstream resolver and collapses response chains in the answer records to just the query name and the queried type.

-> [Modifiers](modifiers.md#response-collapse)

### Router

Routers are used to direct queries to specific upstream resolvers, modifiers, or to other routers based on the query type, name, time of day, or client information.

-> [Routing](routing.md#router)

### ECS Source Routing

The `ecs-source` field allows routing based on the IP address provided in the EDNS Client Subnet (ECS) option ([RFC 7871](https://tools.ietf.org/html/rfc7871)).

-> [Routing](routing.md#ecs-source-routing)

#### Route Evaluation Order

-> [Routing](routing.md#route-evaluation-order)

### Rate Limiter

This element is used to limit the number of queries a client or network is allowed to make in a given time period.

-> [DNSSEC and Rate Limiting](security.md#rate-limiter)

### Fastest TCP Probe

The `fastest-tcp` element will first perform a lookup, then send TCP probes to all A or AAAA records in the response.

-> [Caching and Performance](caching.md#fastest-tcp-probe)

### Retrying Truncated Responses

The `truncated-retry` element will first perform a lookup using its primary resolver.

-> [Caching and Performance](caching.md#retrying-truncated-responses)

### Request Deduplication

The `request-dedup` element passes individual queries to its upstream resolver.

-> [Caching and Performance](caching.md#request-deduplication)

### Syslog

The `syslog` element can be used to log requests and/or responses to local or remote syslog servers.

-> [Logging](observability.md#syslog)

### Query Log

The `query-log` element logs all DNS query details, including time, client IP, DNS question name, class and type.

-> [Logging](observability.md#query-log)

### Lua

Lua groups allow writing custom query handling logic using Lua scripts.

-> [Lua Scripting](scripting.md#lua)

#### Sandbox

-> [Lua Scripting](scripting.md#sandbox)

#### Lua API

-> [Lua Scripting](scripting.md#lua-api)

### DNSSEC Validator

Validates DNSSEC signatures on responses from upstream resolvers.

-> [DNSSEC and Rate Limiting](security.md#dnssec-validator)

### DNS64

Synthesizes AAAA records from A records for IPv6-only clients using NAT64 ([RFC 6147](https://datatracker.ietf.org/doc/html/rfc6147)).

-> [Modifiers](modifiers.md#dns64)

## Resolvers

Resolvers forward queries to other DNS servers over the network and typically represent the end of one or many processing pipelines. See **[Resolvers](resolvers.md)**.

### Bootstrapping

When upstream services are configured using their hostnames, RouteDNS will first have to resolve the hostname of the service before establishing a secure connection with it.

-> [Resolvers](resolvers.md#bootstrapping)

### Plain DNS Resolver

Plain, un-encrypted DNS protocol clients for UDP or TCP.

-> [Resolvers](resolvers.md#plain-dns-resolver)

### DNS-over-TLS Resolver

DNS protocol using a TLS connection (DoT) as per [RFC7858](https://tools.ietf.org/html/rfc7858).

-> [Resolvers](resolvers.md#dns-over-tls-resolver)

### DNS-over-HTTPS Resolver

DNS resolvers using the HTTPS protocol are configured with `protocol = "doh"`.

-> [Resolvers](resolvers.md#dns-over-https-resolver)

### Oblivious DNS (ODoH) Resolver

ODoH ([RFC9230](https://datatracker.ietf.org/doc/rfc9230/)) is intended to improve privacy of **clients** by encrypting queries for a **target** DNS server while sending the query through a **proxy**.

-> [Resolvers](resolvers.md#oblivious-dns-odoh-resolver)

### DNS-over-DTLS Resolver

Similar to DoT, but uses a DTLS (UDP) connection as transport as per [RFC8094](https://tools.ietf.org/html/rfc8094).

-> [Resolvers](resolvers.md#dns-over-dtls-resolver)

### DNS-over-QUIC Resolver

Similar to DoT, but uses a QUIC connection as transport as per [RFC9250](https://datatracker.ietf.org/doc/rfc9250/).

-> [Resolvers](resolvers.md#dns-over-quic-resolver)

### Bootstrap Resolver

Some configurations contain references to external resources by hostname.

-> [Resolvers](resolvers.md#bootstrap-resolver)

### SOCKS5 Proxy Support

Several resolver types support connecting to upstream servers through a SOCKS5 proxy.

-> [Resolvers](resolvers.md#socks5-proxy-support)

### Network Namespace Support

On Linux, listeners and resolvers can be assigned to different network namespaces using the `netns` option.

-> [Resolvers](resolvers.md#network-namespace-support)

#### Without elevated privileges: xsocket

-> [Resolvers](resolvers.md#without-elevated-privileges-xsocket)

### Firewall Mark and Interface Binding

On Linux, listeners and resolvers support two socket-level options for advanced routing.

-> [Resolvers](resolvers.md#firewall-mark-and-interface-binding)

## Templates

Some options hold text with placeholders that are filled in from the query at runtime. See **[Templates](templates.md)**.
