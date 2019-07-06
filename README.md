# RouteDNS - DNS stub resolver and router

RouteDNS acts as a stub resolver that offers flexible configuration options with a focus on providing privacy as well as resiliency. It supports several DNS protocols such as plain UDP and TCP, DNS-over-TLS and DNS-over-HTTPS as input and output. In addition it's possible to build complex configurations allowing routing of queries based on query name, type or source address. Upstream resolvers can be grouped in various ways to provide failover, load-balancing, or performance.

Features:

- Support for DNS-over-TLS (DoT)
- Support for DNS-over-HTTPS (DoH)
- Support for plain DNS, UDP and TCP for incoming and outgoing requests
- Connection reuse and pipelining queries for efficiency
- Multiple failover and load-balancing algorithms
- Custom blocklists
- Routing of queries based on query type, query name, or client IP
- Written in Go - Platform independent

TODO:

- DNS-over-TLS listeners
- DNS-over-HTTP listeners
- Configurable TLS options, like keys and certs
- Dot and DoH listeners should support padding as per [RFC7830](https://tools.ietf.org/html/rfc7830) and [RFC8467](https://tools.ietf.org/html/rfc8467)
- Introduce logging levels

Note: **RouteDNS is under active development and interfaces as well as configuration options are likely going to change**

## Installation

Get the binary

```text
go get -u github.com/folbricht/routedns/cmd/routedns
```

An example systemd service file is provided [here](cmd/routedns/routedns.service)

Example configuration files for a number of use-cases can be found [here](cmd/routedns/example-config)

## Configuration

RouteDNS uses a config file in [TOML](https://github.com/toml-lang/toml) format which is passed to the tool as argument in the command line. The configuration is broken up into sections, not all of which are necessary for simple uses.

### Resolvers

The `[resolvers]`-section is used to define and upstream resolvers and the protocol to use when using them. Each of the resolvers requires a unique identifier which may be reference in the following sections. Only defining the resolvers will not actually mean they are used. This section can contain unused upstream resolvers.

The following protocols are supportes:

- udp - Plain (unencrypted) DNS over UDP
- tcp - Plain (unencrypted) DNS over TCP
- dot - DNS-over-TLS
- doh - DNS-over-HTTP

The following example defines several well-known resolvers, one using DNS-over-TLS, one DNS-over-HTTP while the other two use plain DNS.

```toml
[resolvers]

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

### Groups

Multiple resolvers can be combined into a group to implement different failover or loadbalancing algorithms within that group. Again, each group requires a unique identifier.

Each group has `resolvers` which is and array of one or more resolver-identifiers. These can either be resolvers defined above, or other groups defined earlier.

The `type` determines which algorithm is being used. Available types:

- `round-robin` - Each resolver in the group receives an equal number of queries. There is no failover.
- `fail-rotate` - One resolver is active. If it fails the next becomes active and the request is retried. If the last one fails the first becomes the active again. There's no time-based automatic fail-back.
- `fail-back` - Similar to `fail-rotate` but will attempt to fall back to the original order (prioritizing the first) if there are no failures for a minute.
- `replace` - Applies regular expressions to query strings and replaces them before forwarding the query. Useful to map hostnames to a different domain on-the-fly or append domain names to short hostname queries.

In this example, two upstream resolvers are grouped together and will be used alternating:

```toml
[groups]

  [groups.google-udp]
  resolvers = ["google-udp-8-8-8-8", "google-udp-8-8-4-4"]
  type = "round-robin"
```

### Routers

Routers are used to send queries to specific upstream resolvers, groups, or to other routers based on the query type or name. Routers too require a unique identifier. Each router contains at least one route. Routes are are evaluated in the order they are defined and the first match will be used. Typically the last route should not have a type or name, making it the default route.

A route has the following fields:

- `type` - If defined, only matches queries of this type
- `name` - A regular expession that is applied to the query name. Note that dots in domain names need to be escaped
- `source` - Network in CIDR notation. Used to route based on client IP.
- `resolver` - The identifier of a resolver, group, or another router that was defined earlier.

Below, `router1` sends all queries for the MX record of `google.com` and all its sub-domains to a group consisting of Google's DNS servers. Anything else is sent to a DNS-over-TLS resolver.

```toml
[routers]

  [routers.router1]

    [[routers.router1.routes]]
    type = "MX"
    name = '(^|\.)google\.com\.$'
    resolver="google-udp"

    [[routers.router1.routes]] # A route without type and name becomes the default route for all other queries
    resolver="cloudflare-dot"
```

### Listeners

Listers specify how queries are received and how they should be handled. Listeners can send queries to routers, groups, or to resolvers directly. Listeners have a listen address, a protocol (`udp`, `tcp`, `dot` or `doh`), and specify the handler identifier in `resolver`.

```toml
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

## Use-cases / Examples

### User case 1: Use DNS-over-TLS for all queries locally

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

### User case 2: Prefer secure DNS in a corporate environment

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

    # Send all queries for '*.mycompany.com.' to the company's DNS, possibly through a VPN tunnel
    [[routers.router1.routes]]
    name = '(^|\.)mycompany\.com\.$'
    resolver="mycompany-dns"

    # Everything else can go securely to Cloudflare
    [[routers.router1.routes]]
    resolver="cloudflare-doh-1-1-1-1-get"

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
  type = "blocklist"
  resolvers = ["cleanbrowsing-dot"] # Anything that passes the filter is sent on to this resolver
  blocklist = [                     # Define the names to be blocked
    '(^|\.)facebook.com.$',
    '(^|\.)twitter.com.$',
  ]

[routers]

  [routers.router1]

    [[routers.router1.routes]]
    source = "192.168.1.123/32"    # The IP or network that will use the blocklist in CIDR notation
    resolver="cleanbrowsing-filtered"

    [[routers.router1.routes]]     # Default for everyone else
    resolver="cloudflare-dot"

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

## Links

- DNS-over-TLS RFC - [https://tools.ietf.org/html/rfc7858](https://tools.ietf.org/html/rfc7858)
- DNS-over-HTTPS RFC - [https://tools.ietf.org/html/rfc8484](https://tools.ietf.org/html/rfc8484)
- GoDoc for the rdns library - [https://godoc.org/github.com/folbricht/routedns](https://godoc.org/github.com/folbricht/routedns)
