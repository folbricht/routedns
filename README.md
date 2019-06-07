# RouteDNS - DNS stub resolver and router

RouteDNS acts as a stub resolver that offers flexible configuration options with a focus on providing privacy as well as resiliency. It supports several DNS protocols such as plain UDP and TCP, DNS-over-TLS and DNS-over-HTTPS as input and output. In addition it's possible to build complex configurations allowing routing of queries based on query name or type. Upstream resolvers can be grouped in various ways to provide failover, load-balancing, or performance.

Features:

- Support for DNS-over-TLS
- Support for plain DNS, UDP and TCP for incoming and outgoing traffic
- Connection reuse and pipelining queries for efficiency
- Multiple failover and load-balancing algorithm
- Routing of queries based on type and/or query name

TODO:

- Support for DNS-over-HTTPS resolvers
- Add group for failover algorithm for priority order
- Add group for load-balancing
- Add group for "fastest"
- DNS-over-TLS listeners
- DNS-over-HTTP listeners
- Configurable TLS options, like keys and certs
- Make plain resolvers (TCP & UDP) reuse connections and pipeline queries
- Write tests
- More use-cases/examples

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

The following example defines 3 well-known resolvers, one using DNS-over-TLS while the other two use plain DNS.

```toml
[resolvers]

  [resolvers.cloudflare-dot]
  address = "1.1.1.1:853"
  protocol = "dot"

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
- `name` - A regular expession that is applied to the query name. Note that dots in domain names need to be escaped with \
- `resolver` - The identifier of a resolver, group, or earlier defined router

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

In this example, the goal is to send all DNS queries on the local machine encrypted via DNS-over-TLS to CloudFlare's DSN server `1.1.1.1`. For this, the `nameserver` IP in /etc/resolv.conf is changed to `127.0.0.1`. Since there is only one upstream resolver, and everything should be sent there, no group or router is needed. Both listeners are using the loopback device as only the local machine should be able to use RouteDNS. The config file would look like this:

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

## Links

- DNS-over-TLS RFC - [https://tools.ietf.org/html/rfc7858](https://tools.ietf.org/html/rfc7858)
- DNS-over-HTTPS RFC - [https://tools.ietf.org/html/rfc8484](https://tools.ietf.org/html/rfc8484)
- GoDoc for the rdns library - [https://godoc.org/github.com/folbricht/routedns](https://godoc.org/github.com/folbricht/routedns)
