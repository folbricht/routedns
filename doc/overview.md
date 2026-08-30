# Overview

Part of the [RouteDNS Configuration Guide](configuration.md).

RouteDNS uses a config file in [TOML](https://github.com/toml-lang/toml) format which is passed to the tool as argument on the command line. The configuration is broken up into sections, each of which can contain objects. Each element has a unique identifier (name) which is used to reference it from other objects in order to build a processing pipeline. A configuration can define elements in the following sections, in any order.

- `listeners` - [Listeners](listeners.md#listeners) are effectively DNS servers that receive queries from clients and form the starting point of a pipeline. Listeners are available for several different DNS protocols.
- `routers` - [Routers](routing.md#router) can split a pipeline into multiple processing paths based on query properties such as name, type, or client information.
- `groups` - Everything between a listener and a resolver. This is the largest part of the guide, split by what the component does: [caching and performance](caching.md), [blocklists](blocklists.md), [failover and load balancing](groups.md), [modifiers](modifiers.md), [responders](responders.md), [Lua scripting](scripting.md), [DNSSEC and rate limiting](security.md) and [logging](observability.md).
- `resolvers` - [Resolvers](resolvers.md#resolvers) forward queries to upstream resolvers. They are in effect DNS client implementations that connect to other servers using a variety of protocols.

Not all of these are required to make a working configuration. The most basic configuration could contain a listener (receiver) and a resolver (sender) which would be a simple proxy. The listener and the resolver could use different protocols, making this proxy also a converter.

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

Every feature described in this guide has a working example under [example-config](../cmd/routedns/example-config/), indexed by topic in the README there.

## Split Configuration

Configuration can be broken up into individual files to support large or generated configurations. Split configuration files are passed as arguments to the application:

```text
routedns example-config/split-config/*.toml
```

The same constraints on unique identifiers apply in a split configuration. The individual files are effectively concatenated prior to being loaded.

Example [split-config](../cmd/routedns/example-config/split-config).

## Validating a Configuration

The `--check` option loads a configuration, builds everything it defines, and exits without serving any queries. It exits non-zero if anything failed, so it can be used in CI or before restarting a service.

```text
routedns --check config.toml
routedns --check example-config/split-config/*.toml
```

Building the configuration is what validates it, so `--check` does the same work startup does, short of binding sockets and answering queries. That means it reads certificates and cache files, loads blocklists from their sources (including over HTTP), and connects to Redis. Problems that only appear at that point, such as an unreadable certificate or a blocklist URL that no longer resolves, are reported.

It does not bind any listener address and does not write the cache file, so it is safe to run against the configuration of an instance that is currently serving.

## Writable Paths

Three options write to disk: the cache `filename`, the blocklist `cache-dir`, and the query log `output-file`.

Running RouteDNS directly, these can point anywhere the user can write. Under the systemd unit shipped with the deb, rpm and apk packages, they cannot. That unit uses `DynamicUser=true`, which implies `ProtectSystem=strict` and `PrivateTmp=true`, so the filesystem is read-only apart from a private `/tmp` that systemd discards when the service stops. A path under `/tmp` or `/var/tmp` is therefore worse than one that fails outright: writes succeed and the data is gone on the next restart, with nothing logged to say so.

The unit declares two directories for this:

| Path | Use |
| --- | --- |
| `/var/cache/routedns` | cache `filename`, blocklist `cache-dir` |
| `/var/log/routedns` | query log `output-file` |

```toml
[groups.cached]
type = "cache"
resolvers = ["upstream"]
backend = {type = "memory", filename = "/var/cache/routedns/cache.json", save-interval = 300}
```

systemd creates both on start and preserves their contents across restarts, which matters here because `DynamicUser` allocates a different UID each time.

To write somewhere else, add the location to the unit with `ReadWritePaths=`, or drop `DynamicUser=true` and run as a fixed user that owns the directory.
