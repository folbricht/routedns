# RouteDNS - DNS stub resolver, proxy and router

<<<<<<< Updated upstream
[![GoDoc](https://godoc.org/github.com/folbricht/routedns?status.svg)](https://godoc.org/github.com/folbricht/routedns) ![build](https://github.com/folbricht/routedns/workflows/build/badge.svg)
=======
[![GoDoc](https://godoc.org/github.com/folbricht/routedns?status.svg)](https://godoc.org/github.com/folbricht/routedns) ![build](https://github.com/folbricht/routedns/workflows/build/badge.svg) ![license](https://img.shields.io/badge/License-BSD-green.svg)
>>>>>>> Stashed changes

RouteDNS acts as a stub resolver and proxy that offers flexible configuration options with a focus on providing privacy as well as resiliency. It supports several DNS protocols such as plain UDP and TCP, DNS-over-TLS and DNS-over-HTTPS as input and output. In addition it's possible to build complex configurations allowing routing of queries based on query name, type or source address as well as blocklists and name translation. Upstream resolvers can be grouped in various ways to provide failover, load-balancing, or performance.

Features:

- Support for DNS-over-TLS (DoT, [RFC7858](https://tools.ietf.org/html/rfc7858)), client and server
- Support for DNS-over-HTTPS (DoH, [RFC8484](https://tools.ietf.org/html/rfc8484)), client and server with HTTP2
- Support for DNS-over-QUIC (doq-i00, [draft-ietf-dprive-dnsoquic-00](https://www.ietf.org/id/draft-ietf-dprive-dnsoquic-00.txt)), client and server
- DNS-over-HTTPS using a QUIC transport, client and server
- Custom CAs and mutual-TLS
- Support for plain DNS, UDP and TCP for incoming and outgoing requests
- Connection reuse and pipelining queries for efficiency
- Multiple failover and load-balancing algorithms
- Custom blocklists
- Caching
- In-line query modification and translation
- Routing of queries based on query type, query name, or client IP
- EDNS0 query and response padding ([RFC7830](https://tools.ietf.org/html/rfc7830), [RFC8467](https://tools.ietf.org/html/rfc8467))
- EDNS0 Client Subnet (ECS) manipulation ([RFC7871](https://tools.ietf.org/html/rfc7871))
- Support for bootstrap addresses to avoid the initial service name lookup
- Written in Go - Platform independent

## Installation

Install [Go](https://golang.org/dl) then run the following to build the binary. It'll be placed in $HOME/go/bin by default:

```text
go get -u github.com/folbricht/routedns/cmd/routedns
```

Run it:

```text
routedns config.toml
```

An example systemd service file is provided [here](cmd/routedns/routedns.service)

Example configuration files for a number of use-cases can be found [here](cmd/routedns/example-config)

## Configuration

RouteDNS uses a config file in [TOML](https://github.com/toml-lang/toml) format which is passed to the tool as argument in the command line. The configuration is broken up into sections, not all of which are necessary for simple uses.

The config file defines listeners which represent open ports and protocols on which incoming DNS queries are received. These queries are then forwarded to routers, groups or resolvers. Routers can redirect queries based on information in the query, while groups can be be used to perform failover between upstream resolvers, or to modify/block queries. A more complex configuration could look like this.

![configuration](doc/configuration.png)

Configuration files can be broken up into individual files to support large or generated configurations. Split configuration files are passed as arguments:

```text
routedns example-config/split-config/*.toml
```

Example [split-config](cmd/routedns/example-config/split-config).

### Resolvers

The `[resolvers]`-section is used to define and upstream resolvers and the protocol to use when using them. Each of the resolvers requires a unique identifier which may be reference in the following sections. Only defining the resolvers will not actually mean they are used. This section can contain unused upstream resolvers.

The following protocols are supportes:

- udp - Plain (unencrypted) DNS over UDP
- tcp - Plain (unencrypted) DNS over TCP
- dot - DNS-over-TLS
- doh - DNS-over-HTTP
- doq - DNS-over-QUIC

The following example defines several well-known resolvers, one using DNS-over-TLS, one DNS-over-HTTP while the other two use plain DNS. A more extensive list of configurations for public DNS services can be found [here](cmd/routedns/example-config/well-known.toml).

```toml
[resolvers.cloudflare-dot]
address = "1.1.1.1:853"
protocol = "dot"

[resolvers.cloudflare-doh]
address = "https://1.1.1.1/dns-query{?dns}"
protocol = "doh"

[resolvers.google-udp-8-8-8-8]
address = "8.8.8.8:53"
protocol = "udp"

[resolvers.google-udp-8-8-4-4]
address = "8.8.4.4:53"
protocol = "udp"
```

Secure resolvers (DoT and DoH) also support additional option to set the trusted CA certificates or even set client key and certificates. Certificate and key files need to be in PEM format. Specify `ca` to only trust a specific set of CAs. If not specified, the resolver will use the system trust store.

```toml
[resolvers.cloudflare-dot-with-ca]
address = "1.1.1.1:853"
protocol = "dot"
ca = "/path/to/DigiCertECCSecureServerCA.pem"
```

For full mutual TLS with a private DNS server that expects the client to present a certificate, the `client-key` and `client-crt` options can be used to specify the key and certificate files.

```toml
[resolvers.my-mutual-tls]
address = "myserver:853"
protocol = "dot"
ca = "/path/to/my-ca.pem"
client-key = "/path/to/my-key.pem"
client-crt = "/path/to/my-crt.pem"
```

#### Bootstrapping

When upstream services are configured using their hostnames, routedns will first have to resolve the hostname of the service before establishing a secure connection with it. There are a couple of potenial issues with this:

- The initial lookup is using the OS' resolver which could be using plain unencrypted DNS. This may not be desirable or fail if no other DNS is available.
- The service does not support querying it by IP directly and a hostname is needed. Google for example does not support DoH using `https://8.8.8.8/dns-query`. The endpoint has to be configured as `https://dns.google/dns-query`.

To solve these issues, it is possible to add a bootstrap IP address to the config. This will use the IP to connect to the service without first having to do a lookup while still preserving the DoH URL or DoT hostname for the TLS handshake. The `bootstrap-address` option is available on both, DoT and DoH resolvers.

```toml
[resolvers.google-doh-post-bootstrap]
address = "https://dns.google/dns-query"
protocol = "doh"
bootstrap-address = "8.8.8.8"
```

### Groups

Multiple resolvers can be combined into a group to implement different failover or loadbalancing algorithms within that group. Some groups are used as query modifiers (e.g. blocklist or caches) and can be chained with other groups or routers. Again, each group requires a unique identifier.

Each group has `resolvers` which is and array of one or more resolver-identifiers. These can either be resolvers defined above, or other groups defined earlier.

The `type` determines which algorithm is being used. Available types:

- `round-robin` - Each resolver in the group receives an equal number of queries. There is no failover.
- `fail-rotate` - One resolver is active. If it fails the next becomes active and the request is retried. If the last one fails the first becomes the active again. There's no time-based automatic fail-back.
- `fail-back` - Similar to `fail-rotate` but will attempt to fall back to the original order (prioritizing the first) if there are no failures for a minute.
- `replace` - Applies regular expressions to query strings and replaces them before forwarding the query. Useful to map hostnames to a different domain on-the-fly or append domain names to short hostname queries.
- `blocklist-v2` - A blocklist has just one upstream resolver and forwards anything that does not match its filters. If a query matches, it'll be answered with NXDOMAIN or a spoofed IP. See [blocklists](#Blocklists) for more information. Note that `blocklist` is still supported by lacks features of `blocklist-v2` such as multiple lists, or allowlists that skip the filters.
- `cache` - Caches responses for the amount of time in the TTL of answer, NS, and extra records.

In this example, two upstream resolvers are grouped together and will be used alternating:

```toml
[groups.google-udp]
resolvers = ["google-udp-8-8-8-8", "google-udp-8-8-4-4"]
type = "round-robin"
```

### Routers

Routers are used to send queries to specific upstream resolvers, groups, or to other routers based on the query type or name. Routers too require a unique identifier. Each router contains at least one route. Routes are are evaluated in the order they are defined and the first match will be used. Typically the last route should not have a class, type or name, making it the default route.

A route has the following fields:

- `type` - If defined, only matches queries of this type
- `class` - If defined, only matches queries of this class ("IN", "CH", "HS", "NONE", "ANY")
- `name` - A regular expession that is applied to the query name. Note that dots in domain names need to be escaped
- `source` - Network in CIDR notation. Used to route based on client IP.
- `resolver` - The identifier of a resolver, group, or another router that was defined earlier.

Below, `router1` sends all queries for the MX record of `google.com` and all its sub-domains to a group consisting of Google's DNS servers. Anything else is sent to a DNS-over-TLS resolver.

```toml
[routers.router1]
routes = [
  { name = '(^|\.)google\.com\.$', type = "MX", resolver="google-udp" },
  { resolver="cloudflare-dot" }, # default route
]
```

### Listeners

Listers specify how queries are received and how they should be handled. Listeners can send queries to routers, groups, or to resolvers directly. Listeners have a listen address, a protocol (`udp`, `tcp`, `dot`, `doh`, `doq`), and specify the handler identifier in `resolver`.

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

Some listeners, namely DoH and DoT, can be configured with certificates and can enforce mutual-TLS. A secure listener of this type requires at least the `server-crt` and `server-key` options. Other options such as `ca` and `mutual-tls` can be used in more secure configurations. A listener using DoH and requiring client certificates would look like this:

```toml
[listeners.local-doh]
address = ":443"
protocol = "doh"
resolver = "upstream-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
ca = "/path/to/ca.crt"
mutual-tls = true
```

It is possible to only allow querying a listener from a number of client networks using the `allowed-net` option. Clients outside the allowed networks will receive answers with a status of `REFUSED`. By default, a listener allows all clients which can be restricted like so:

```toml
[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "cloudflare-dot"
allowed-net = ["127.0.0.1/32", "::1/128", "192.168.0.0/16"]
```

## QUIC support

Support for the QUIC protocol is still experimental. For the purpose of DNS, there are two implementations, DNS-over-QUIC ([draft-ietf-dprive-dnsoquic-00](https://www.ietf.org/id/draft-ietf-dprive-dnsoquic-00.txt)) as well as DNS-over-HTTPS using QUIC. Both methosd are supported by RouteDNS, client and server implementations.

### DNS-over-QUIC

DoQ is similar to DoT in that it used standard DNS encoding, but over a QUIC transport stream. There is no overhead from HTTP. No official port has been assigned yet but 784/udp is recommended for experimentation.

Use `protocol = "doq"` to start a listener (server). All the other options of secure listeners like `server-crt`, `server-key`, `ca`, and `mutual-tls` are supported as well.

```toml
[listeners.local-doq]
address = ":784"
protocol = "doq"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
```

The same `protocol = "doq"` is used on the resolver (client) side. Like with the other resolvers, use `bootstrap-address` to bypass the lookup of the server address itself.

```toml
[resolvers.local-doq]
address = "server.acme.test:784"
protocol = "doq"
ca = "/path/to/ca.crt"
bootstrap-address = "127.0.0.1"
```

### DNS-over-HTTPS with QUIC

DoH with QUIC is similar to regular DoH with the transport protocol being different. The HTTP routes and methods are the same. To enable QUIC on the listener or resolver, add the `transport = "quic"` option. Everything else remains the same.

Example listener config:

```toml
[listeners.local-doh-quic]
address = ":443"
protocol = "doh"
transport = "quic"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
```

Example resolver config:

```toml
[resolvers.cloudflare-doh-quic]
address = "https://cloudflare-dns.com/dns-query{?dns}"
protocol = "doh"
transport = "quic"
```

## Blocklists

### Query blocklists

Query blocklists can be added to resolver-chains to prevent further processing and either return NXDOMAIN or a spoofed IP address for a DNS query that matches a rule on the blocklist. The blocklist group supports 3 types of blocklist formats:

- `regexp` - The entire query string is matched against a list of regular expressions and NXDOMAIN returned if a match is found.
- `domain` - A list of domains with some wildcard capabilities. Also results in an NXDOMAIN. Entries in the list are matched as follows:
  - `domain.com` matches just domain.com and no sub-domains.
  - `.domain.com` matches domain.com and all sub-domains.
  - `*.domain.com` matches all subdomains but not domain.com. Only one wildcard (at the start of the string) is allowed.
- `hosts` - A blocklist in hosts-file format. If a non-zero IP address is provided for a record, the response is spoofed rather than returning NXDOMAIN.

The following options are supported by the `blocklist-v2` type:

- `blocklist-resolver` - Alternative resolver for queries matching the blocklist, rather than responding with NXDOMAIN.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided.
- `blocklist-refresh` - Time interval in which external (remote or local) blocklists are reloaded.
- `blocklist-soure` - An array of blocklists, each with `format` and `source`.
- `allowlist-resolver` - Alternative resolver for queries matching the allowlist, rather than forwarding to the default resolver.
- `allowlist-format` - The format the allowlist is provided in. Only used if `allowlist-source` is not provided.
- `allowlist-refresh` - Time interval in which external (remote or local) allowlists are reloaded.
- `allowlist-soure` - An array of allowlists, each with `format` and `source`.

Multiple blocklists of different types can be chained in the same configuration. Example of a regexp-based blocklist:

```toml
[groups.my-blocklist]
type             = "blocklist-v2"
resolvers        = ["upstream-resolver"] # Anything that passes the filter is sent on to this resolver
blocklist-format ="regexp"               # "domain", "hosts" or "regexp", defaults to "regexp"
blocklist        = [                     # Define the names to be blocked
  '(^|\.)evil\.com\.$',
  '(^|\.)unsafe[123]\.org\.$',
```

Example of a blocklist using a domain-list:

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

In addition to reading the blocklist rules from the configuration file, routedns supports reading from the local filesystem and from remote servers via HTTP(S). Use the `blocklist-source` property of the blocklist to provide a list of blocklists of different formats, either local files or URLs. The `blocklist-refresh` property can be used to specify a reload-period (in seconds). If no `blocklist-refresh` period is given, the blocklist will only be loaded once at startup. The following example loads a regexp blocklist via HTTP once a day.

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

To override the blocklist filtering behavior, the properties `allowlist`, `allowlist-format`, `allowlist-source` and `allowlist-refresh` can be used to define inverse filters. They are used just like the equivalent blocklist-options, but are effectively inverting its behavior. A query matching a rule on the allowlist will be passing through the blocklist and not be blocked. Here an example of a blocklist with 2 filtering lists, and a allow-list that overrides the filtering behavior.

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

### Response blocklists

Rather than filtering queries, response blocklists evaluate the response to a query and block anything that matches a filter-rule. There are two kinds of response blocklists: `response-blocklist-cidr` and `response-blocklist-name`.

- `response-blocklist-cidr` blocks backed on IP networks (in CIDR notation) on A or AAAA responses.
- `response-blocklist-name` filters based on domain names in CNAME, MX, NS, PRT and SRV records.

The configuration options of response blocklists are very similar to that of [query blocklists](#Queryblocklists) with the exception of the allowlists options which are not currently supported. If the `filter` option is set to `true` in `response-blocklist-cidr`, matching records will be removed from responses rather than the whole response. If there is no answer record left after applying the filter, NXDOMAIN will be returned.

Examples of simple response blocklists with static rules in the configuration file.

```toml
[groups.cloudflare-blocklist]
type                = "response-blocklist-cidr"
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

Response blocklists that use local or remote rulesets with periodic refresh.

```toml
[groups.cloudflare-blocklist]
type              = "response-blocklist-cidr"
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

## EDNS0 Client Subnet modifier

A client subnet modifier is used to either remove ECS options from a query, replace/add one, or improve privacy by hiding more bits of the address. This is done with the `ecs-modifier` group which supports the following operations:

- `add` - Add an ECS option to a query. If there is one already it is replaced. If no `ecs-address` is provided, the address of the client is used (with `ecs-prefix4` or `ecs-prefix6` applied).
- `delete` - Remove the ECS option completely from the EDNS0 record.
- `privacy` - Restrict the number of bits in the address to the number in `ecs-prefix4`/`ecs-prefix6`.

Some of the operations require additional options:

- `ecs-op` - Operation to be performed on query options. Either "add", "delete", or "privacy". Does nothing if not specified.
- `ecs-address` - The address to use in the option. Only used for add operations. If give, will set to a fixed value. If missing, the address of the client is used (with the appropriate `ecs-prefix` applied).
- `ecs-prefix4` and `ecs-prefix6` - Source prefix length. Mask for the address. Only used for add and privacy operations.

Remove ECS options from all queries.

```toml
[groups.google-ecs]
type = "ecs-modifier"
resolvers = ["google-dot"]
ecs-op = "delete" # "add", "delete", "privacy". Defaults to "" which does nothing.
```

Add/replace ECS options in all queries fixed network address. Without `ecs-address`, this will use the client's IP address.

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

## Static responders

A `static-responder` can be used to terminate a query with a fixed answer. The answer can contain Answer, NS, and Extra records with a configurable RCode. Static responsers are useful in combination with routers to build walled-gardens or blocklists providing more control over the response. The individual records in the response are defined in zone-file format. The default TTL is 1h unless given in the record.

A fixed responder that will return a full answer with NS and Extra records with different TTL. The name string in answer records gets updated dynamically to match the query, while NS and Extra records are return unmodified.

```toml
[groups.static-a]
type   = "static-responder"
rcode  = 0 # Response code: 0 = NOERROR, 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ...
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
rcode = 3
```

## Use-cases / Examples

### Use case 1: Use DNS-over-TLS for all queries locally

In this example, the goal is to send all DNS queries on the local machine encrypted via DNS-over-TLS to Cloudflare's DNS server `1.1.1.1`. For this, the `nameserver` IP in /etc/resolv.conf is changed to `127.0.0.1`. Since there is only one upstream resolver, and everything should be sent there, no group or router is needed. Both listeners are using the loopback device as only the local machine should be able to use RouteDNS. The config file would look like this:

```toml
[resolvers]

  [resolvers.cloudflare-dot]
  address = "1.1.1.1:853"
  protocol = "dot"

[listeners]

  [listeners.local-udp]
  address = "127.0.0.1:53"
  protocol = "udp"
  resolver = "cloudflare-dot"

  [listeners.local-tcp]
  address = "127.0.0.1:53"
  protocol = "tcp"
  resolver = "cloudflare-dot"
```

### Use case 2: Prefer secure DNS in a corporate environment

In a corporate environment it's necessary to use the potentially slow and insecure company DNS servers. Only these servers are able to resolve some resources hosted in the corporate network. A router can be used to secure DNS whenever possible while still being able to resolve internal hosts.

```toml
[resolvers]

  # Define the two company DNS servers. Both use plain (insecure) DNS over UDP
  [resolvers.mycompany-dns-a]
  address = "10.0.0.1:53"
  protocol = "udp"

  [resolvers.mycompany-dns-b]
  address = "10.0.0.2:53"
  protocol = "udp"

  # Define the Cloudflare DNS-over-HTTPS resolver (GET methods) since that is most likely allowed outbound
  [resolvers.cloudflare-doh-1-1-1-1-get]
  address = "https://1.1.1.1/dns-query{?dns}"
  protocol = "doh"
  doh = { method = "GET" }

[groups]

  # Since the company DNS servers have a habit of failing, group them into a group that switches on failure
  [groups.mycompany-dns]
  resolvers = ["mycompany-dns-a", "mycompany-dns-b"]
  type = "fail-rotate"

[routers]

  [routers.router1]
  routes = [
    { name = '(^|\.)mycompany\.com\.$', resolver="mycompany-dns" }, # Use company DNS, perhaps through a VPN tunnel
    { resolver="cloudflare-doh-1-1-1-1-get" },                      # Everything else can go securely to Cloudflare
  ]

[listeners]

  [listeners.local-udp]
  address = "127.0.0.1:53"
  protocol = "udp"
  resolver = "router1"

  [listeners.local-tcp]
  address = "127.0.0.1:53"
  protocol = "tcp"
  resolver = "router1"
```

### Use case 3: Restrict access to potentially harmful content

The goal here is to single out children's devices on the network and apply a custom blocklist to their DNS resolution. Anything on the blocklist will fail to resolve with an NXDOMAIN response. Names that aren't on the blocklist are then sent on to CleanBrowsing for any further filtering. All other devices on the network will have unfiltered access via Cloudflare's DNS server, and all queries are done using DNS-over-TLS. The config file can also be found [here](cmd/routedns/example-config/family-browsing.toml)

```toml
[resolvers]

  [resolvers.cleanbrowsing-dot]
  address = "family-filter-dns.cleanbrowsing.org:853"
  protocol = "dot"

  [resolvers.cloudflare-dot]
  address = "1.1.1.1:853"
  protocol = "dot"

[groups]

  [groups.cleanbrowsing-filtered]
  type = "blocklist-v2"
  resolvers = ["cleanbrowsing-dot"] # Anything that passes the filter is sent on to this resolver
  blocklist = [                     # Define the names to be blocked
    '(^|\.)facebook\.com\.$',
    '(^|\.)twitter\.com\.$',
  ]

[routers]

  [routers.router1]
  routes = [
    { source = "192.168.1.123/32", resolver="cleanbrowsing-filtered" }, # The IP or network that will use the blocklist in CIDR notation
    { resolver="cloudflare-dot" }, # Default for everyone else
  ]

[listeners]

  [listeners.local-udp]
  address = ":53"
  protocol = "udp"
  resolver = "router1"

  [listeners.local-tcp]
  address = ":53"
  protocol = "tcp"
  resolver = "router1"
```

### Use case 4: Replace queries for short names with FQDN

If adding a search list to /etc/resolv.conf is not an option, a `replace` group can be used to add the correct domain based on the name in the query. It's possible to modify or expand query strings by matching on a regex and replacing it with an alternative expression. The replace string supports expansion like `$1` to refer to a match in the regex. The `replace` can be combined with routers and resolvers as with all the other groups.

In this example, queries for short names starting with `my-` will have the domain `home-domain.com.` appended to them and the prefix removed. A query for `my-server.` from the client will result in a query for `server.home-domain.com.` to Cloudflare. The response to the client will reference `my-server.` with the response from Cloudflare. More than one replace rule can be defined and they are applied to the query name in order. Any other queries will pass without modification.

```toml
[resolvers]

  [resolvers.cloudflare-dot]
  address = "1.1.1.1:853"
  protocol = "dot"

[groups]

  [groups.append-my-domain]
  type = "replace"
  resolvers = ["cloudflare-dot"]
  replace = [
    { from = '^my-([^.]+\.)$', to = '${1}home-domain.com.' },
  ]

[listeners]

  [listeners.local-udp]
  address = ":53"
  protocol = "udp"
  resolver = "append-my-domain"
```

### Use case 5: Proxying out of a restricted or untrusted location

In this use case the goal is to use get access to unfiltered and unmonitored DNS services in a location that does not offer it normally. Direct access to well-known public DoT or DoH providers may be blocked, forcing plain DNS. It may be possible to setup an instansce of RouteDNS in a less restricted location to act as proxy, offering DoH which is harder to detect and block. To prevent unauthorized access to the proxy, the config will enforce mutual-TLS with a client certificate signed by a custom CA.

The following config on the server will accept queries over DNS-over-HTTPS from authorized clients (with valid and signed certificate), and forward all queries to Cloudflare using DNS-over-TLS.

```toml
[resolvers]

  [resolvers.cloudflare-dot]
  address = "1.1.1.1:853"
  protocol = "dot"

[listeners]

  [listeners.proxy-doh]
  address = ":443"
  protocol = "doh"
  resolver = "cloudflare-dot"
  server-crt = "/path/to/server.crt"
  server-key = "/path/to/server.key"
  ca = "/path/to/ca.crt"
  mutual-tls = true
```

The client is configured to act as local DNS resolver, handling all queries from the local OS. Every query is then forwarded to the proxy using DoH. The client needs to have a signed certificate as the proxy is configured to require it.

```toml
[resolvers]

  [resolvers.proxy-doh]
  address = "https://<Proxy-IP>:443/dns-query"
  protocol = "doh"
  ca = "/path/to/ca.crt"
  client-crt = "/path/to/client.crt"
  client-key = "/path/to/client.crt"

[listeners]

  [listeners.local]
  address = ":53"
  protocol = "udp"
  resolver = "proxy-doh"
```

## Links

- DNS-over-TLS RFC - [https://tools.ietf.org/html/rfc7858](https://tools.ietf.org/html/rfc7858)
- DNS-over-HTTPS RFC - [https://tools.ietf.org/html/rfc8484](https://tools.ietf.org/html/rfc8484)
- EDNS0 padding [RFC7830](https://tools.ietf.org/html/rfc7830) and [RFC8467](https://tools.ietf.org/html/rfc8467)
- Go QUIC implementation - [https://github.com/lucas-clemente/quic-go](https://github.com/lucas-clemente/quic-go)
- Go DNS library - [https://github.com/miekg/dns](https://github.com/miekg/dns)
