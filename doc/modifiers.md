# Modifiers

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | **Modifiers** | [Responders](responders.md) | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | [Templates](templates.md)

## Replace

`type = "replace"`

The replace modifier applies regular expressions to query strings and replaces them before forwarding the query to the upstream resolver or modifier. The response is then mapped back to the original query, similar to NAT in a network. This can be useful to map hostnames to different domains on-the-fly or to append domain names to short hostname queries. In lab environments, one can replace a query for a production host with the equivalent lab host.

### Configuration

Replace groups are instantiated with `type = "replace"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `replace` - Array of maps with `from` and `to` to represent the mapping.
  - `from` - Regular expression that is applied to the query name. Can contain regexp groups `(...)` which can be used in the `to` expression.
  - `to` - Expression to replace any matches in `from` with. Can reference regexp groups with `${1}`.

### Examples

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

## EDNS0 Client Subnet Modifier

`type = "ecs-modifier"`

A client subnet modifier is used to either remove ECS options from a query, replace/add one, or improve privacy by hiding more bits of the address. The following operation are supported by the subnet modifier:

- `add` - Add an ECS option to a query. If there is one already it is replaced. If no `ecs-address` is provided, the address of the client is used (with `ecs-prefix4` or `ecs-prefix6` applied).
- `add-if-missing` - Add an ECS option to a query if none was provided by the client. If no `ecs-address` is provided, the address of the client is used (with `ecs-prefix4` or `ecs-prefix6` applied).
- `delete` - Remove the ECS option completely from the EDNS0 record.
- `privacy` - Restrict the number of bits in the address to the number in `ecs-prefix4`/`ecs-prefix6`.

### Configuration

Client Subnet modifiers are instantiated with `type = "ecs-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `ecs-op` - Operation to be performed on query options. Either `add`, `add-if-missing`, `delete`, or `privacy`. Does nothing if not specified.
- `ecs-address` - The address to use in the option. Only used for add operations. If given, will set the address to a fixed value. If missing, the address of the client is used (with the appropriate `ecs-prefix` applied).
- `ecs-prefix4` and `ecs-prefix6` - Source prefix length. Mask for the address. Only used for add and privacy operations.

### Examples

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

**Related Feature**: If you want to route queries based on ECS data, see [ECS Source Routing](routing.md#ecs-source-routing). While `EDNS0 Client Subnet Modifier` focuses on modifying ECS data before forwarding it upstream, `ECS Source Routing` enables routing decisions based on the original client's IP address in ECS data.

## EDNS0 Modifier

`type = "edns0-modifier"`

EDNS0 Modifier allows low-level operations on the EDNS0 option records in queries. It can be used to add or remove custom option codes with arbitrary data.

- `add` - Add an EDNS0 option to a query. If there is one already it is replaced.
- `delete` - Remove the specified option from the EDNS0 options.

### Configuration

EDNS0 Subnet modifiers are instantiated with `type = "edns0-modifier"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `edns0-op` - Operation to be performed on query options. Either `add`, `delete`. Note that `add` replaces options with the same code if present.
- `edns0-code` - EDNS0 option code to apply the modification to.
- `edns0-data` - Raw data for the option expressed in an array of (decimal!) byte values. Only used for `add` operations.

### Examples

Add the MAC address 52:54:00:b6:49:60 to an EDNS0 option (code 65001) for identification with the upstream resolver.

```toml
[groups.opendns-mac]
type = "edns0-modifier"
resolvers = ["opendns"]
edns0-op = "add" # "add" or "delete". Defaults to "" which does nothing.
edns0-code = 65001
edns0-data = [82, 84, 0, 182, 73, 96]
```

Example config files: [edns0-modifier.toml](../cmd/routedns/example-config/edns0-modifier.toml)

## Response Minimizer

`type = "response-minimize"`

This element passes all queries to its upstream resolver and strips all Extra and NS records from the response, making responses smaller.

### Configuration

A response minimizer is instantiated with `type = "response-minimize"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.

### Examples

```toml
[groups.minimize]
type = "response-minimize"
resolvers = ["google-dot"]
```

Example config files: [response-minimize.toml](../cmd/routedns/example-config/response-minimize.toml)

## Response Collapse

`type = "response-collapse"`

This element passes all queries to its upstream resolver and collapses response chains in the answer records to just the query name and the queried type.

A response chain like this:

```text
www.paypal.com. 2964 IN CNAME www.glb.paypal.com.
www.glb.paypal.com. 251 IN CNAME www.paypal.com-a.edgekey.net.
www.paypal.com-a.edgekey.net. 7199 IN CNAME e5308.x.akamaiedge.net.
e5308.x.akamaiedge.net. 18 IN A 95.100.196.60
```

Becomes:

```text
www.paypal.com. 18 IN A 95.100.196.60
```

### Configuration

A response collapse element is instantiated with `type = "response-collapse"` in the groups section of the configuration.

Options:

- `null-rcode` - Response code if after collapsing there are no answer records left: 0 = NOERROR (default), 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ... See [rfc2929#section-2.3](https://tools.ietf.org/html/rfc2929#section-2.3)

### Examples

```toml
[groups.collapse]
type = "response-collapse"
resolvers = ["google-dot"]
```

Example config files: [response-collapse.toml](../cmd/routedns/example-config/response-collapse.toml)

## DNS64

`type = "dns64"`

Synthesizes AAAA records from A records for IPv6-only clients using NAT64 ([RFC 6147](https://datatracker.ietf.org/doc/html/rfc6147)). When an AAAA query returns no AAAA answers from upstream, DNS64 falls back to an A query and embeds the IPv4 addresses into configurable IPv6 prefixes per [RFC 6052](https://datatracker.ietf.org/doc/html/rfc6052). Queries for non-AAAA types and responses that already contain AAAA records pass through unchanged.

### Configuration

A DNS64 group is instantiated with `type = "dns64"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers (only one supported).
- `dns64-prefix` - Array of IPv6 CIDR prefixes for address synthesis. Supported prefix lengths: `/32`, `/40`, `/48`, `/56`, `/64`, `/96`. Default: `["64:ff9b::/96"]` (well-known prefix from RFC 6052).

### Examples

Using the well-known prefix (default):

```toml
[groups.dns64]
type = "dns64"
resolvers = ["upstream-udp"]
```

Custom prefix:

```toml
[groups.dns64]
type = "dns64"
resolvers = ["upstream-udp"]
dns64-prefix = ["2001:db8::/96"]
```

Multiple prefixes:

```toml
[groups.dns64]
type = "dns64"
resolvers = ["upstream-udp"]
dns64-prefix = ["64:ff9b::/96", "2001:db8::/32"]
```
