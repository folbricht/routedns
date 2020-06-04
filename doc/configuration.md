# RouteDNS Configuration Guide

## Table of contents

- [Overview](#Overview)
  - [Split Configuration](#Split-Configuration)
- [Listeners](#Listeners)
  - [Plain DNS](#Plain-DNS)
  - [DNS-over-TLS](#DNS-over-TLS)
  - [DNS-over-HTTPS](#DNS-over-HTTPS)
  - [DNS-over-DTLS](#DNS-over-DTLS)
  - [DNS-over-QUIC](#DNS-over-QUIC)
- [Modifiers, Groups and Routers](#Modifiers-Groups-and-Routers)
  - [Cache](#Cache)
  - [TTL Modifier](#TTL-modifier)
  - [Round-Robin group](#Round-Robin-group)
  - [Fail-Rotate group](#Fail-Rotate-group)
  - [Fail-Back group](#Fail-Back-group)
  - [Replace](#Replace)
  - [Query Blocklist](#Query-Blocklist)
  - [Response Blocklist](#Response-Blocklist)
  - [EDNS0 Client Subnet modifier](#EDNS0-Client-Subnet-Modifier)
  - [Static responder](#Static-responder)
  - [Router](#Router)
- [Resolvers](#Resolvers)
  - [Plain DNS](#Plain-DNS-Resolver)
  - [DNS-over-TLS](#DNS-over-TLS-Resolver)
  - [DNS-over-HTTPS](#DNS-over-HTTPS-Resolver)
  - [DNS-over-DTLS](#DNS-over-DTLS-Resolver)
  - [DNS-over-QUIC](#DNS-over-QUIC-Resolver)

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

Secure listeners, such as DNS-over-TLS, DNS-over-HTTPS, DNS-over-DTLS, DNS-over-QUIC support additional options to configure certificate, keys and peer validation

- `server-crt` - Server certificate file. Required.
- `server-key` - Server key file. Required.
- `ca` - CA to validate client certificated. Optional. Uses the operating system's CA store by default.
- `mutual-tls` - Requires clients to send valid (as per `ca` option) certificates before establishing a connection. Optional.

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

As per [RFC8484](https://tools.ietf.org/html/rfc8484), DNS using the HTTPS protocol are configured with `protocol = "doh"`. By default, DoH uses TCP as transport, but it can also be run over QUIC by providing the option `transport = "quic"`.

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

Example config files: [mutual-tls-doh-server.toml](../cmd/routedns/example-config/mutual-tls-doh-server.toml), [doh-quic-server.toml](../cmd/routedns/example-config/doh-quic-server.toml)

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

Similar to DoT, but uses a QUIC connection as transport as per [draft-ietf-dprive-dnsoquic-00](https://www.ietf.org/id/draft-ietf-dprive-dnsoquic-00.txt). Configured with `protocol = "doq"`. Note that this is different from DoH over QUIC. See [DNS-over-HTTPS](#DNS-over-HTTPS) for how to configure this.

Note: Support for the QUIC protocol is still experimental. For the purpose of DNS, there are two implementations, DNS-over-QUIC ([draft-ietf-dprive-dnsoquic-00](https://www.ietf.org/id/draft-ietf-dprive-dnsoquic-00.txt)) as well as DNS-over-HTTPS using QUIC. Both methods are supported by RouteDNS, client and server implementations.

Examples:

DoQ listener accepting queries from all clients.

```toml
[listeners.local-doq]
address = ":1784"
protocol = "doq"
resolver = "cloudflare-dot"
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

Example config files: [doq-listener.toml](../cmd/routedns/example-config/doq-listener.toml)

## Modifiers, Groups and Routers

### Cache

A cache will store the responses to queries in memory and respond to further identical queries with the same response. To determine how long an item is kept in memory, the cache uses the lowest TTL of the RRs in the response. Responses served from the cache have their TTL updated according to the time the records spent in memory.

Caches can be combined with a [TTL Modifier](#TTL-Modifier) to avoid too many cache-misses due to excessively low TTL values.

#### Configuration

Caches are instantiated with `type = "cache"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `cache-size` - Max number of responses to cache. Defaults to 0 which means no limit. Optional
- `cache-negative-ttl` - TTL (in seconds) to apply to responses without a SOA. Default: 60. Optional

#### Examples

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

### TTL modifier

A TTL modifier is used to adjust the time-to-live (TTL) of DNS responses. This is used to avoid frequently making the same queries to upstream because many responses have a value that is unreasonably low as outlined in this [blog](https://blog.apnic.net/2019/11/12/stop-using-ridiculously-low-dns-ttls). It's also possible to restrict very high TTL values that might be used in DNS poisoning attacks.

The limits are applied to all RRs in a response.

#### Configuration

Caches are instantiated with `type = "ttl-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `ttl-min` - TTL minimum (in seconds) to apply to responses
- `ttl-max` - TTL minimum (in seconds) to apply to responses

#### Examples

TTL modifier that returns responses with TTL of between 1h and one day:

```toml
[groups.cloudflare-updated-ttl]
type = "ttl-modifier"
resolvers = ["cloudflare-dot"]
ttl-min = 3600
ttl-max = 86400
```

Example config files: [ttl-modifier.toml](../cmd/routedns/example-config/ttl-modifier.toml)

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

In a Fail-Rotate group, one of the upstream resolvers or modifiers is active and receives all queries. If the active resolver fails, the next becomes active and the request is retried. If the last resolver fails the first becomes the active again. There's no time-based automatic fail-back.

#### Configuration

Round-Robin groups are instantiated with `type = "fail-rotate"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.

#### Examples

```toml
[groups.google-udp]
resolvers = ["google-udp-8-8-8-8", "google-udp-8-8-4-4"]
type = "fail-rotate"
```

### Fail-Back group

Similar to [fail-rotate](#Fail-Rotate-group) but will attempt to fall back to the original order (prioritizing the first) if there are no failures for a minute.

#### Configuration

Fail-Back groups are instantiated with `type = "fail-back"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers. The first in the array is the preferred resolver.

#### Examples

```toml
[groups.my-failback-group]
resolvers = ["company-dns", "cloudflare-dot"]
type = "fail-back"
```

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
- `blocklist-source` - An array of blocklists, each with `format` and `source`.
- `allowlist-resolver` - Alternative resolver for queries matching the allowlist, rather than forwarding to the default resolver.
- `allowlist-format` - The format the allowlist is provided in. Only used if `allowlist-source` is not provided. Can be `regexp`, `domain`, or `hosts`. Defaults to `regexp`.
- `allowlist-refresh` - Time interval (in seconds) in which external allowlists are reloaded. Optional.
- `allowlist-source` - An array of allowlists, each with `format` and `source`.

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
```

Simple blocklist with static `domain`-format rule in the configuration.

```toml
[groups.my-blocklist]
type            = "blocklist-v2"
resolvers       = ["upstream-resolver"]
bloclist-format = "domain"
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

Blocklist that loads two rule-sets. One from an HTTP server, the other from a file on disk. Both are reloaded once a day.

```toml
[groups.cloudflare-blocklist]
type = "blocklist-v2"
resolvers = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source = [
   {format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/master/deugniets/routedns.blocklist.domain.list"},
   {format = "regexp", source = "/path/to/local/regexp.list"},
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

Example config files: [blocklist-regexp.toml](../cmd/routedns/example-config/blocklist-regexp.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml), [blocklist-domain.toml](../cmd/routedns/example-config/blocklist-domain.toml), [blocklist-hosts.toml](../cmd/routedns/example-config/blocklist-hosts.toml), [blocklist-local.toml](../cmd/routedns/example-config/blocklist-local.toml), [blocklist-remote.toml](../cmd/routedns/example-config/blocklist-remote.toml), [blocklist-allow.toml](../cmd/routedns/example-config/blocklist-allow.toml), [blocklist-resolver.toml](../cmd/routedns/example-config/blocklist-resolver.toml)

### Response Blocklist

Rather than filtering queries, response blocklists evaluate the response to a query and block anything that matches a filter-rule. There are two kinds of response blocklists: `response-blocklist-ip` and `response-blocklist-name`.

- `response-blocklist-ip` blocks backed on IP addresses in the response, by network IP (in CIDR notation) or geographical location.
- `response-blocklist-name` filters based on domain names in CNAME, MX, NS, PRT and SRV records.

#### Configuration

The configuration options of response blocklists are very similar to that of [query blocklists](#Query-Blocklist) with the exception of the `allowlists-*` options which are not supported in response blocklists.

Query blocklists are instantiated with `type = "response-blocklist-ip"` or `type = "response-blocklist-name"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `blocklist-resolver` - Alternative resolver for responses matching a rule, the query will be re-sent to this resolver. Optional.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided.
  - For `response-blocklist-ip`, the value can be `cidr`, or `location`. Defaults to `cidr`.
  - For `response-blocklist-name`, the value can be `regexp`, `domain`, or `hosts`. Defaults to `regexp`.
- `blocklist-refresh` - Time interval (in seconds) in which external (remote or local) blocklists are reloaded. Optional.
- `blocklist-source` - An array of blocklists, each with `format` and `source`.
- `filter` - If set to `true` in `response-blocklist-ip`, matching records will be removed from responses rather than the whole response. If there is no answer record left after applying the filter, NXDOMAIN will be returned.
- `location-db` - If location-based IP blocking is used, this specifies the GeoIP data file to load. Optional. Defaults to /usr/share/GeoIP/GeoLite2-City.mmdb

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

### EDNS0 Client Subnet Modifier

A client subnet modifier is used to either remove ECS options from a query, replace/add one, or improve privacy by hiding more bits of the address. The following operation are supported by the subnet modifier:

- `add` - Add an ECS option to a query. If there is one already it is replaced. If no `ecs-address` is provided, the address of the client is used (with `ecs-prefix4` or `ecs-prefix6` applied).
- `delete` - Remove the ECS option completely from the EDNS0 record.
- `privacy` - Restrict the number of bits in the address to the number in `ecs-prefix4`/`ecs-prefix6`.

#### Configuration

Round-Robin groups are instantiated with `type = "ecs-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `ecs-op` - Operation to be performed on query options. Either `add`, `delete`, or `privacy`. Does nothing if not specified.
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

### Static responder

A static responder can be used to terminate every query made to it with a fixed answer. The answer can contain Answer, NS, and Extra records with a configurable RCode. Static responders are useful in combination with routers to build walled-gardens or blocklists providing more control over the response. The individual records in the response are defined in zone-file format. The default TTL is 1h unless given in the record.

#### Configuration

Round-Robin groups are instantiated with `type = "static-responder"` in the groups section of the configuration.

Options:

- `rcode` - Response code: 0 = NOERROR, 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ... See [rfc2929#section-2.3](https://tools.ietf.org/html/rfc2929#section-2.3) for a more complete list. Defaults to 0 (No Error).
- `answer` - Array of strings, each one representing a line in zone-file format. Forms the content of the Answer records in the response.
- `ns` - Array of strings, each one representing a line in zone-file format. Forms the content of the Authority records in the response.
- `extra` - Array of strings, each one representing a line in zone-file format.  Forms the content of the Additional records in the response.

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
[groups.static-nxdomain]
type  = "static-responder"
rcode = 3 # NXDOMAIN
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

Example config files: [walled-garden.toml](../cmd/routedns/example-config/walled-garden.toml), [rfc8482.toml](../cmd/routedns/example-config/rfc8482.toml),

### Router

Routers are used to direct queries to specific upstream resolvers, modifier, or to other routers based on the query type, name, or client information. Each router contains at least one route. Routes are are evaluated in the order they are defined and the first match will be used. Routes that match on the query name are regular expressions. Typically the last route should not have a class, type or name, making it the default route.

#### Configuration

Routers groups are instantiated with `routers.NAME` with NAME being a unique identifier for this router.

Options:

- `routes` - Array of routes. Routes are processed in order and processing stops after the first match.

A route has the following fields:

- `type` - If defined, only matches queries of this type, `A`, `AAAA`, `MX`, etc. Optional.
- `class` - If defined, only matches queries of this class (`IN`, `CH`, `HS`, `NONE`, `ANY`). Optional.
- `name` - A regular expression that is applied to the query name. Note that dots in domain names need to be escaped. Optional.
- `source` - Network in CIDR notation. Used to route based on client IP. Optional.
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

Route queries from a specific IP to a different resolver.

```toml
[routers.router1]
routes = [
  { source = "192.168.1.123/32", resolver="cleanbrowsing-filtered" },
  { resolver="cloudflare-dot" },
]
```

Example config files: [split-dns.toml](../cmd/routedns/example-config/split-dns.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml), [family-browsing.toml](../cmd/routedns/example-config/family-browsing.toml),[walled-garden.toml](../cmd/routedns/example-config/walled-garden.toml)

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

Secure resolvers such as DoT, DoH, or DoQ offer additional options to configure the TLS connections.

- `client-crt` - Client certificate file.
- `client-key` - Client certificate key file
- `ca` - CA certificate to validate server certificates.

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

To solve these issues, it is possible to add a bootstrap IP address to the config. This will use the IP to connect to the service without first having to perform a lookup while still preserving the DoH URL or DoT hostname for the TLS handshake. The `bootstrap-address` option is available on both, DoT and DoH resolvers.

```toml
[resolvers.google-doh-post-bootstrap]
address = "https://dns.google/dns-query"
protocol = "doh"
bootstrap-address = "8.8.8.8"
```

### Plain DNS Resolver

Plain, un-encrypted DNS protocol clients for UDP or TCP. Use `protocol = "udp"` or `protocol = "tcp"`.

Examples:

```toml
[resolvers.google-udp-8-8-8-8]
address = "8.8.8.8:53"
protocol = "udp"

[resolvers.cloudflare-tcp]
address = "1.1.1.1:53"
protocol = "tcp"
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml)

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
address = "https://cloudflare-dns.com/dns-query"
protocol = "doh"
transport = "quic"
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml), [simple-doh.toml](../cmd/routedns/example-config/simple-doh.toml), [mutual-tls-doh-client.toml](../cmd/routedns/example-config/mutual-tls-doh-client.toml)

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

Similar to DoT, but uses a QUIC connection as transport as per [draft-ietf-dprive-dnsoquic-00](https://www.ietf.org/id/draft-ietf-dprive-dnsoquic-00.txt). Configured with `protocol = "doq"`. Note that this is different from DoH over QUIC. See [DNS-over-HTTPS](#DNS-over-HTTPS-Resolver) for how to configure this.

Examples:

```toml
[resolvers.local-doq]
address = "server.acme.test:1784"
protocol = "doq"
ca = "example-config/server.crt"
bootstrap-address = "127.0.0.1"
```

Example config files: [doq-client.toml](../cmd/routedns/example-config/doq-client.toml)
