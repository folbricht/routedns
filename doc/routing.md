# Routing

Part of the [RouteDNS Configuration Guide](configuration.md).

## Router

Routers are used to direct queries to specific upstream resolvers, modifiers, or to other routers based on the query type, name, time of day, or client information. Each router contains at least one route. Routes are evaluated in the order they are defined and the first match will be used. Routes that match on the query name are regular expressions. Typically the last route should not have a class, type or name, making it the default route.

### Configuration

Routers groups are instantiated with `routers.NAME` with NAME being a unique identifier for this router.

Options:

- `routes` - Array of routes. Routes are processed in order and processing stops after the first match.

A route has the following fields:

- `type` - If defined, only matches queries of this type, `A`, `AAAA`, `MX`, etc. Optional.
- `types` - List of types. If defined, only matches queries whose type is in this list. Optional.
- `class` - If defined, only matches queries of this class (`IN`, `CH`, `HS`, `NONE`, `ANY`). Optional.
- `name` - A regular expression that is applied to the query name. Note that dots in domain names need to be escaped. To match case-insensitive, prefix with `(?i)`, e.g. `"(?i)example\.com$"`. See [Syntax](https://github.com/google/re2/wiki/Syntax) for details. Optional.
- `source` - Network in CIDR notation. Used to route based on client IP. Optional.
- `ecs-source` - Network in CIDR notation. Used to route based on the IP address in the EDNS Client Subnet (ECS) option. Optional.
- `weekdays` - List of weekdays this route should match on. Possible values: `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`. Uses local time, not UTC.
- `after` - Time of day in the format HH:mm after which the rule matches. Uses 24h format. For example `09:00`. Note that together with the `before` parameter it is possible to accidentally write routes that can never trigger. For example `after=12:00 before=11:00` can never match as both conditions have to be met for the route to be used.
- `before` - Time of day in the format HH:mm before which the rule matches. Uses 24h format. For example `17:30`.
- `invert` - Invert the result of the matching if set to `true`. Optional.
- `doh-path` - Regexp that matches on the DoH query path the client used.
- `listener` - Regexp that matches on the ID of the listener that first received.
- `servername` - Regexp that matches on the TLS server name used in the TLS handshake with the listener.
- `resolver` - The identifier of a resolver, group, or another router. Required.

For all regular expressions, see [Syntax](https://github.com/google/re2/wiki/Syntax) on what is supported. To match case-insensitive, prefix with `(?i)`, e.g. `"(?i)example\.com$"`.

### Examples

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

## ECS Source Routing

The `ecs-source` field allows routing based on the IP address provided in the EDNS Client Subnet (ECS) option ([RFC 7871](https://tools.ietf.org/html/rfc7871)). This is useful when RouteDNS is behind a resolver or proxy that forwards the original client IP using ECS, such as Dnsmasq with `add-subnet=32`. Since all queries arrive at RouteDNS from the same source IP (the proxy), standard `source` routing cannot differentiate between clients.

**Important:** To prevent leaking ECS data to upstream resolvers, use an `ecs-modifier` with `ecs-op = "delete"` before forwarding queries. ECS data contains information about the original client's IP address, which may compromise privacy if shared with upstream resolvers. Removing ECS data ensures that upstream resolvers only see the proxy's IP address.

**Security note — ECS is client-controlled:** Unlike `source`, which is derived from the transport connection and cannot be forged, `ecs-source` matches on the ECS option carried in the query itself. Any client that can reach RouteDNS directly can put an arbitrary address in that option and steer routing — bypassing security-relevant policies such as parental controls or per-network filtering. `ecs-source` is only safe for policy decisions when the ECS value is written by a component you trust:

- RouteDNS must **not** be directly reachable by untrusted clients. Place it behind the trusted forwarder/proxy that adds the ECS option and firewall off direct access.
- Constrain the route with `source` so the ECS value is only honored when the query actually arrives from the trusted proxy, for example `{ source = "10.0.0.1/32", ecs-source = "192.168.1.10/32", resolver = "..." }`. Both conditions must match (logical AND), so a query from any other source IP will not match the ECS route regardless of its ECS contents.
- Prefer a forwarder that **replaces** the client's ECS option rather than appending to it. RouteDNS evaluates the *last* ECS option in the query, so a proxy that appends its own option after a client-supplied one will take precedence; a proxy that appends but leaves the client's option untouched is still safe, but one that does not normalize at all is not.

Note also that the router runs *before* groups in the pipeline, so an `ecs-modifier` group cannot normalize ECS ahead of the routing decision unless it is placed between the listener and the router (`listener → ecs-modifier → router`).

### Route Evaluation Order

Routes are evaluated sequentially, and the first matching route is used. **Order matters** when defining routes:
- More specific routes (e.g., `192.168.1.10/32`) should be placed **before** broader routes (e.g., `192.168.1.0/24`).
- If a broader route is placed first, it will match all queries within that subnet, and the more specific route will never be evaluated.

### Examples

Route queries based on ECS data:

```toml
[routers.ecs-router]
routes = [
  # Route 1: Queries with an ECS source of 192.168.1.10/32 are sent to the adblocker.
  { ecs-source = "192.168.1.10/32", resolver = "adblock-resolver" },

  # Route 2: Queries with an ECS source of 192.168.1.0/24 are sent to the unfiltered resolver.
  { ecs-source = "192.168.1.0/24", resolver = "unfiltered-resolver" },

  # Route 3 (Default): All other queries (including those without ECS) go to the unfiltered resolver.
  { resolver = "unfiltered-resolver" },
]
```

Combine ECS routing with ECS removal:

```toml
[routers.ecs-router]
routes = [
  { ecs-source = "192.168.1.10/32", resolver = "adblock-resolver" },
  { resolver = "remove-ecs" },
]

[groups.remove-ecs]
type = "ecs-modifier"
resolvers = ["upstream-resolver"]
ecs-op = "delete"
```

**Related Feature**: If you want to control what ECS data is sent to upstream resolvers, see [EDNS0 Client Subnet modifier](modifiers.md#edns0-client-subnet-modifier). While `ECS Source Routing` focuses on routing decisions based on ECS data, `EDNS0 Client Subnet Modifier` allows you to add, remove, or restrict ECS data for privacy or compatibility.
