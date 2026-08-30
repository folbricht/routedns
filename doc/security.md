# DNSSEC and Rate Limiting

Part of the [RouteDNS Configuration Guide](configuration.md).

## Rate Limiter

This element is used to limit the number of queries a client or network is allowed to make in a given time period. It uses a fixed window algorithm and by default drops any queries that exceed the configured maximum. Alternatively, a `limit-resolver` can be configured to route such queries to other elements such as [static responders](responders.md#static-responder) or other resolvers.

### Configuration

A rate limiter element is instantiated with `type = "rate-limiter"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `limit-resolver` - Upstream element to route rate-limited requests to. Optional, default behavior is to drop such queries.
- `requests` - Number of requests allowed per time period.
- `window` - Number of seconds in the time period, default 60.
- `prefix4` - Prefix length for identifying an IPv4 client, default 24
- `prefix6` - Prefix length for identifying an IPv6 client, default 56

### Examples

Simple rate-limiter allowing 200 requests per minute from the same /24 (or /56) networks.

```toml
[groups.rrl]
type = "rate-limiter"
resolvers = ["cloudflare-dot"]
requests = 200
```

Rate-limiter allowing 100 queries from a /24 (or /56) network per 2 minutes. Queries that exceed the limit will be answered with REFUSED.

```toml
[groups.rrl]
type = "rate-limiter"
resolvers = ["cloudflare-dot"]
limit-resolver = "static-refused"
requests = 100
window = 120
prefix4 = 24
prefix6 = 56

[groups.static-refused]
type  = "static-responder"
rcode = 5 # REFUSED
```

Example config files: [rate-limiter.toml](../cmd/routedns/example-config/rate-limiter.toml)

## DNSSEC Validator

Validates DNSSEC signatures on responses from upstream resolvers. The validator builds a chain of trust from configured root trust anchors down through DS and DNSKEY records to verify RRSIG signatures on the response. If validation fails, a SERVFAIL is returned to the client. Unsigned zones (insecure delegations) pass through without error. Only NOERROR and NXDOMAIN responses are validated.

By default, the validator uses the built-in IANA root trust anchors (KSK-2017 and KSK-2024). Custom trust anchors can be provided to override the defaults, or the validator can fetch them from a URL at startup.

### Configuration

A DNSSEC validator is instantiated with `type = "dnssec-validator"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers (only one supported).
- `dnssec-log-only` - If `true`, validation failures are logged but responses are still returned to clients. Useful for monitoring before enforcing. Default: `false`.
- `dnssec-trust-anchor-url` - Optional URL to fetch trust anchors from at startup. The URL should serve XML in IANA root-anchors.xml format. Expired entries (past their `validUntil` date) are automatically filtered out. If the fetch fails, falls back to built-in defaults. Ignored if `dnssec-trust-anchors` is set.
- `dnssec-trust-anchors` - Optional array of trust anchors. If not provided, the built-in IANA root KSK-2017 and KSK-2024 are used. Each entry has the following fields:
  - `owner` - Owner name of the trust anchor (e.g. `"."`).
  - `key-tag` - Key tag of the DNSKEY.
  - `algorithm` - DNSSEC algorithm number.
  - `digest-type` - Digest type number.
  - `digest` - Hex-encoded digest of the DNSKEY.

### Examples

Simple DNSSEC validation with default trust anchors:

```toml
[groups.dnssec-validated]
type = "dnssec-validator"
resolvers = ["cloudflare-dot"]
```

Auto-fetch trust anchors from IANA:

```toml
[groups.dnssec-validated]
type = "dnssec-validator"
resolvers = ["cloudflare-dot"]
dnssec-trust-anchor-url = "https://data.iana.org/root-anchors/root-anchors.xml"
```

Log-only mode with explicit trust anchors:

```toml
[groups.dnssec-validated]
type = "dnssec-validator"
resolvers = ["cloudflare-dot"]
dnssec-log-only = true

# KSK-2017
[[groups.dnssec-validated.dnssec-trust-anchors]]
owner = "."
key-tag = 20326
algorithm = 8
digest-type = 2
digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

# KSK-2024
[[groups.dnssec-validated.dnssec-trust-anchors]]
owner = "."
key-tag = 38696
algorithm = 8
digest-type = 2
digest = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
```

Example config files: [dnssec-validator.toml](../cmd/routedns/example-config/dnssec-validator.toml), [dnssec-validator-trust-anchors.toml](../cmd/routedns/example-config/dnssec-validator-trust-anchors.toml), [dnssec-validator-iana.toml](../cmd/routedns/example-config/dnssec-validator-iana.toml)
