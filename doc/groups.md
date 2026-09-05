# Failover and Load Balancing

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | **Failover and Load Balancing** | [Modifiers](modifiers.md) | [Responders](responders.md) | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | [Templates](templates.md)

## Round-Robin group

`type = "round-robin"`

A Round-Robin balancer groups multiple upstream resolvers and sends every received query to the next resolver. It effectively balances the query load evenly over a number of upstream resolvers or modifiers.

### Configuration

Round-Robin groups are instantiated with `type = "round-robin"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.

### Examples

```toml
[groups.google-udp]
resolvers = ["google-udp-8-8-8-8", "google-udp-8-8-4-4"]
type = "round-robin"
```

## Fail-Rotate group

`type = "fail-rotate"`

In a Fail-Rotate group, one of the upstream resolvers or modifiers is active and receives all queries. If the active resolver fails, i.e. no response or returns SERVFAIL, the next becomes active and the request is retried. If the last resolver fails the first becomes the active again. There's no time-based automatic fail-back.

### Configuration

Fail-Rotate groups are instantiated with `type = "fail-rotate"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.
- `servfail-error` - If `true`, a SERVFAIL response from an upstream resolver is considered a failure triggering a switch to the next resolver. This can happen when DNSSEC validation fails for example. Default `false`.
- `empty-error` - If `true`, an empty response (including NXDOMAIN) from an upstream resolver is considered a failure triggering a switch to the next resolver. Responses with EDE codes Blocked/Censored/Filtered are still considered successful. Default `false`.

### Examples

```toml
[groups.google-udp]
resolvers = ["google-udp-8-8-8-8", "google-udp-8-8-4-4"]
type = "fail-rotate"
```

## Fail-Back group

`type = "fail-back"`

Similar to [fail-rotate](#fail-rotate-group) but will attempt to fall back to the original order (prioritizing the first) if there are no failures for a minute. Failure means either no response or it returns SERVFAIL.

### Configuration

Fail-Back groups are instantiated with `type = "fail-back"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers. The first in the array is the preferred resolver.
- `reset-after` - Non-zero time in seconds before switching from an alternative resolver back to the preferred resolver (first in the list), or a negative number to switch back immediately, default 60. Note: This is not a timeout argument. After a failure of the preferred resolver, this defines the amount of time to use alternative/failover resolvers before switching back to the preferred. You can have as many resolvers in the array as the time limit allows.
- `servfail-error` - If `true`, a SERVFAIL response from an upstream resolver is considered a failure triggering a failover. This can happen when DNSSEC validation fails for example. Default `false`.
- `empty-error` - If `true`, an empty response (including NXDOMAIN) from an upstream resolver is considered a failure triggering a switch to the next resolver. Responses with EDE codes Blocked/Censored/Filtered are still considered successful. Default `false`.

### Examples

```toml
[groups.my-failback-group]
resolvers = ["company-dns", "cloudflare-dot"]
type = "fail-back"
```

## Random group

`type = "random"`

This group will pick a resolver from its list of upstream resolvers at random. Resolvers that fail will be deactivated for an amount of time before being re-tried.

### Configuration

Random groups are instantiated with `type = "random"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.
- `reset-after` - Non-zero time in seconds to disable a failed resolver, or a negative number to disable only for a single request, default 60.
- `servfail-error` - If `true`, a SERVFAIL response from an upstream resolver is considered a failure which will take the resolver temporarily out of the group. This can happen when DNSSEC validation fails for example. Default `false`.
- `empty-error` - If `true`, an empty response (including NXDOMAIN) from an upstream resolver is considered a failure triggering a switch to the next resolver. Responses with EDE codes Blocked/Censored/Filtered are still considered successful. Default `false`.

### Examples

```toml
[groups.random]
type   = "random"
resolvers = ["cloudflare-dot-1", "cloudflare-dot-2", "google-dot"]
```

Example config files: [random-resolver.toml](../cmd/routedns/example-config/random-resolver.toml)

## Load-Balance group

`type = "load-balance"`

This group distributes queries across all configured resolvers using weighted random selection based on measured response times. Resolvers with lower average response times receive proportionally more traffic. If the selected resolver fails, the query is retried with another resolver until one succeeds or all have been tried.

Compared to [Fail-Rotate](#fail-rotate-group) and [Fail-Back](#fail-back-group), load is spread across all resolvers at all times rather than concentrating on one until it fails. Compared to [Random](#random-group), selection is weighted by measured response time so faster resolvers naturally receive more traffic; resolvers are never removed from the pool — on failure their EMA is only allowed to move upward (preventing fast-failing resolvers from appearing artificially fast), and the optional `failure-penalty` accelerates suppression after persistent failures. Compared to [Fastest](#fastest-group), each query goes to a single resolver rather than all of them simultaneously.

On startup all resolvers have equal weight. Weights adjust automatically as response-time data accumulates. To keep the pool healthy, weighting is bounded and self-correcting: a small share of queries (~5%) is sent to a uniformly-chosen resolver regardless of weight, so even penalized or slow resolvers keep being re-measured and can recover rather than being starved; the response time used for weighting is floored at 1ms, so an exceptionally fast resolver cannot completely crowd out slower ones; and once a previously-penalized resolver succeeds again its average is re-seeded to the freshly measured time instead of slowly decaying, allowing it to regain traffic quickly.

The current per-resolver response-time average (in microseconds) is exported via expvar as `routedns.router.<id>.rtt`, keyed by resolver, alongside the usual `route`, `failure`, `available`, and `failover` metrics.

### Configuration

Load-Balance groups are instantiated with `type = "load-balance"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.
- `failure-penalty` - Penalty in seconds injected into a failed resolver's response-time average after 2 consecutive failures, accelerating its suppression beyond the baseline upward-only EMA clamp. A single transient failure is absorbed without penalty. Default `0` (disabled).
- `servfail-error` - If `true`, a SERVFAIL response from an upstream resolver is considered a failure triggering a retry with another resolver. This can happen when DNSSEC validation fails for example. Default `false`.
- `empty-error` - If `true`, an empty response (including NXDOMAIN) from an upstream resolver is considered a failure triggering a retry with another resolver. Responses with EDE codes Blocked/Censored/Filtered are still considered successful. Default `false`.

### Examples

```toml
[groups.load-balanced]
type = "load-balance"
resolvers = ["cloudflare-dot-1", "cloudflare-dot-2", "google-dot"]
failure-penalty = 5
```

Example config files: [load-balance.toml](../cmd/routedns/example-config/load-balance.toml)

## Fastest group

`type = "fastest"`

This group will send every query to all configured resolvers but only use the fastest (successful) response. Slower responses are discarded. Use sparingly as this increases the overall query load on upstream resolvers.

### Configuration

Fastest groups are instantiated with `type = "fastest"` in the groups section of the configuration.

Options:

- `resolvers` - An array of upstream resolvers or modifiers.

### Examples

```toml
[groups.fastest]
type   = "fastest"
resolvers = ["cloudflare-dot-1", "cloudflare-dot-2", "google-dot"]
```

Example config files: [fastest.toml](../cmd/routedns/example-config/fastest.toml)
