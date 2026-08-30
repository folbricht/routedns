# Blocklists

Part of the [RouteDNS Configuration Guide](configuration.md).

## Query Blocklist

Query blocklists can be added to resolver-chains to prevent further processing of queries (return NXDOMAIN or spoofed IP) or to send queries to different resolvers if the query name matches a rule on the blocklist. A blocklist can have multiple rule-sets, with different formats. In its simplest form, the blocklist has just one upstream resolver and forwards anything that does not match its rules. If a query matches, it'll be answered with NXDOMAIN or a spoofed IP, depending on what blocklist format is used.

The blocklist group supports 5 types of blocklist formats:

- `regexp` - The entire query string is matched against a list of regular expressions and NXDOMAIN returned if a match is found. See [Syntax](https://github.com/google/re2/wiki/Syntax) for details on what is supported.
- `domain` - A list of domains with some wildcard capabilities. Also results in an NXDOMAIN. Entries in the list are matched as follows:
  - `domain.com` matches just domain.com and no sub-domains.
  - `.domain.com` matches domain.com and all sub-domains.
  - `*.domain.com` matches all subdomains but not domain.com. Only one wildcard (at the start of the string) is allowed.
- `domain-subdomain` - Like `domain`, but bare entries (e.g. `domain.com`) match the apex *and* all sub-domains. `.domain.com` is unchanged. `*.domain.com` still matches sub-domains only and can be used as a per-entry opt-out. Designed for blocklists such as hagezi's "Wildcard Domains" lists where every line is meant to block apex + sub-domains.
- `hosts` - A blocklist in hosts-file format. If a non-zero IP address is provided for a record, the response is spoofed rather than returning NXDOMAIN.
- `mac` - A blocklist of MAC addresses in the form `01:23:34:ab:bc:de` representing the MAC address of a client. The query is expected to contain the value of the client's MAC in EDNS0 option 65001.

In addition to reading the blocklist rules from the configuration file, routedns supports reading from the local filesystem and from remote servers via HTTP(S). Use the `blocklist-source` property of the blocklist to provide a list of blocklists of different formats, either local files or URLs. The `blocklist-refresh` property can be used to specify a reload-period (in seconds). If no `blocklist-refresh` period is given, the blocklist will only be loaded once at startup. The following example loads a regexp blocklist via HTTP once a day.

To override the blocklist filtering behavior, the properties `allowlist`, `allowlist-format`, `allowlist-source` and `allowlist-refresh` can be used to define inverse filters. They are used just like the equivalent blocklist-options, but are effectively inverting its behavior. A query matching a rule on the allowlist will be passing through the blocklist and not be blocked.

### Configuration

Query blocklists are instantiated with `type = "blocklist-v2"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `blocklist-resolver` - Alternative resolver for queries matching the blocklist, rather than responding with NXDOMAIN. Optional.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided. Can be `regexp`, `domain`, `domain-subdomain`, or `hosts`. Defaults to `regexp`.
- `blocklist-refresh` - Time interval (in seconds) in which external (remote or local) blocklists are reloaded. Optional.
- `blocklist-source` - An array of blocklists, each with `format`, `source` and optionally `name`.
- `allowlist-resolver` - Alternative resolver for queries matching the allowlist, rather than forwarding to the default resolver.
- `allowlist-format` - The format the allowlist is provided in. Only used if `allowlist-source` is not provided. Can be `regexp`, `domain`, `domain-subdomain`, or `hosts`. Defaults to `regexp`.
- `allowlist-refresh` - Time interval (in seconds) in which external allowlists are reloaded. Optional.
- `allowlist-source` - An array of allowlists, each with `format`, `source`, and optionally `cache-dir` or `allow-failure`.
- `edns0-ede` - Optional, include an extended error code in the response if it's blocked. Only used when the response is blocked, not when it's spoofed. The value is a struct with two keys, `code` (number) and `text` (string). Possible values for `code` are defined in [rfc8914](https://datatracker.ietf.org/doc/html/rfc8914) while `text` can carry additional information that is displayed by `dig` for example. The `text` value is a template that has access to a number of fields of query to allow customizing the response based on data in the query. See [Templates](templates.md#templates) for details. Simple placeholders in `text` would be `{{ .Question }}` for the question in the query or `{{ .ID }}` to be replaced with the query ID.

When using the `cache-dir` option on a list that loads rules via HTTP, the results are cached into a file in the given directory. The filename is the URL of the source hashed with SHA256 so multiple blocklists can be cached in the same directory. If a cached file exists on startup, it is used instead of refreshing the list from the remote location (slowing down startup). As with the cache `filename` option, a new file is created with mode `0600` and an existing one keeps whatever mode it already has. When running under the systemd unit shipped with the packages, use a path under `/var/cache/routedns`; see [Writable Paths](overview.md#writable-paths).

To avoid errors at startup when for example a remote blocklist isn't available, the `allow-failure` option can be used. Any errors encountered will be logged but not cause a failure to start. If a failure occurs during runtime, the previous ruleset will be reused.

### Examples

Simple blocklist with static regexp rules defined in the configuration:

```toml
[groups.my-blocklist]
type             = "blocklist-v2"
resolvers        = ["upstream-resolver"] # Anything that passes the filter is sent on to this resolver
blocklist-format ="regexp"               # "domain", "hosts" or "regexp", defaults to "regexp"
blocklist        = [                     # Define the names to be blocked
  '(?i)(^|\.)evil\.com\.$',
  '(^|\.)unsafe[123]\.org\.$',
]
```

Simple blocklist with static `domain`-format rule in the configuration. This will respond with an extended error code and a message containing the question name.

```toml
[groups.my-blocklist]
type             = "blocklist-v2"
resolvers        = ["upstream-resolver"]
blocklist-format = "domain"
edns0-ede        = {code = 15, text = "Blocked {{ .Question }} because rule {{ .BlocklistRule }} on {{ .Blocklist}}"}
blocklist = [
  'domain1.com',               # Exact match
  '.domain2.com',              # Exact match and all sub-domains
  '*.domain3.com',             # Only match sub-domains
]
```

Blocklist using the `domain-subdomain` format. Bare entries match the apex *and* all sub-domains, so a single line such as `evil.com` blocks `evil.com`, `www.evil.com`, etc. A `*.opt-out.com` entry can still be used to block sub-domains only and leave the apex resolvable. Useful for lists like hagezi's "Wildcard Domains" where every line is meant to apply to apex + sub-domains.

```toml
[groups.my-blocklist]
type             = "blocklist-v2"
resolvers        = ["upstream-resolver"]
blocklist-format = "domain-subdomain"
blocklist = [
  'evil.com',         # Blocks evil.com and all sub-domains
  'facebook.com',     # Blocks facebook.com and all sub-domains
  '*.opt-out.com',    # Blocks sub-domains only; apex still resolves
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

Blocklist that loads two rule-sets. One from an HTTP server, the other from a file on disk. Both are reloaded once a day. A `name` can be provided which will be used in logs instead of `source`.

```toml
[groups.cloudflare-blocklist]
type = "blocklist-v2"
resolvers = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source = [
   {name = "cbuijs/blocklist", format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/main/malicious-dom/routedns.blocklist.domain.list"},
   {format = "regexp", source = "/path/to/local/regexp.list"},
]
```

Remote blocklist that is cached to local disk (`cache-dir="/var/cache/routedns"`) and loaded from it at startup. It also ignores failures to load the remote blocklist and does not prevent startup.

```toml
[groups.cloudflare-blocklist]
type = "blocklist-v2"
resolvers = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source = [
   {format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/main/malicious-dom/routedns.blocklist.domain.list", cache-dir = "/var/cache/routedns", allow-failure = true},
]
```

Blocklist that loads 2 remote blocklists daily, and also defines a local allowlist which overrides the blocklist rules. Anything matching a rule on the allowlist is forwarded to an alternative resolver or modifier, `"trusted-resolver"` in this case (not shown in the example).

```toml
[groups.cloudflare-blocklist]
type = "blocklist-v2"
resolvers = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source = [
   {format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/main/malicious-dom/routedns.blocklist.domain.list"},
   {format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/main/easylist/routedns.blocklist.domain.list"},
]
allowlist-resolver = "trusted-resolver" # Send anything on the allowlist to a different upstream resolver (optional)
allowlist-refresh = 86400
allowlist-source = [
   {format = "domain", source = "/path/to/trustworthy.list"},
]
```

Example config files: [blocklist-regexp.toml](../cmd/routedns/example-config/blocklist-regexp.toml), [block-split-cache.toml](../cmd/routedns/example-config/block-split-cache.toml), [blocklist-domain.toml](../cmd/routedns/example-config/blocklist-domain.toml), [blocklist-hosts.toml](../cmd/routedns/example-config/blocklist-hosts.toml), [blocklist-local.toml](../cmd/routedns/example-config/blocklist-local.toml), [blocklist-remote.toml](../cmd/routedns/example-config/blocklist-remote.toml), [blocklist-allow.toml](../cmd/routedns/example-config/blocklist-allow.toml), [blocklist-resolver.toml](../cmd/routedns/example-config/blocklist-resolver.toml), [blocklist-domain-ede.toml](../cmd/routedns/example-config/blocklist-domain-ede.toml), [blocklist-mac.toml](../cmd/routedns/example-config/blocklist-mac.toml)

## Response Blocklist

Rather than filtering queries, response blocklists evaluate the response to a query and block anything that matches a filter-rule. There are two kinds of response blocklists: `response-blocklist-ip` and `response-blocklist-name`.

- `response-blocklist-ip` blocks based on IP addresses in the response, by network IP (in CIDR notation) or geographical location.
- `response-blocklist-name` filters based on domain names in CNAME, MX, NS, PTR and SRV records.

### Configuration

The configuration options of response blocklists are very similar to that of [query blocklists](#query-blocklist) with the exception of the `allowlists-*` options which are not supported in response blocklists.

Response blocklists are instantiated with `type = "response-blocklist-ip"` or `type = "response-blocklist-name"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `blocklist-resolver` - Alternative resolver for responses matching a rule, the query will be re-sent to this resolver. Optional.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided.
  - For `response-blocklist-ip`, the value can be `cidr`, or `location`. Defaults to `cidr`.
  - For `response-blocklist-name`, the value can be `regexp`, `domain`, or `hosts`. Defaults to `regexp`.
- `blocklist-refresh` - Time interval (in seconds) in which external (remote or local) blocklists are reloaded. Optional.
- `blocklist-source` - An array of blocklists, each with `format`, `source` and optionally `cache-dir` (see notes for [Query Blocklist](#query-blocklist)) as well as `name` which assigns a name to the list used in logs (defaults to `source`).
- `filter` - If set to `true` in `response-blocklist-ip`, matching records will be removed from responses rather than the whole response. If there is no answer record left after applying the filter, NXDOMAIN will be returned unless an alternative `blocklist-resolver` is defined.
- `inverted` - Inverts the behavior of the blocklist. If set to `true`, only IPs that are on the blocklist are allowed and responses containing an IP not on the blocklist are blocked. Can be combined with `filter` to remove any IPs not on the blocklist from the response.
- `location-db` - If location-based IP blocking is used, this specifies the GeoIP data file to load. Optional. Defaults to /usr/share/GeoIP/GeoLite2-City.mmdb
- `edns0-ede` - Optional, include an extended error code in the response if it's blocked. Only used when the response is blocked, not when it's spoofed. The value is a struct with two keys, `code` (number) and `text` (string). Possible values for `code` are defined in [rfc8914](https://datatracker.ietf.org/doc/html/rfc8914) while `text` can carry additional information that is displayed by `dig` for example. The `text` value is a template that has access to a number of fields of query to allow customizing the response based on data in the query. See [Templates](templates.md#templates) for details. Simple placeholders in `text` would be `{{ .Question }}` for the question in the query or `{{ .ID }}` to be replaced with the query ID. Only `response-blocklist-ip` acts on this option; it is ignored by `response-blocklist-name`.

Location-based blocking requires a list of GeoName IDs of geographical entities (Continent, Country, City or Subdivision) and the GeoName ID, like `2750405` for Netherlands. The GeoName ID can be looked up in [https://www.geonames.org/](https://www.geonames.org/). Locations are read from a MAXMIND GeoIP2 database that either has to be present in `/usr/share/GeoIP/GeoLite2-City.mmdb` or is configured with the `location-db` option. Similarly, using a different location database (`/usr/share/GeoIP/GeoLite2-ASN.mmdb`) it is possible to block IP responses located in specific ASNs (Autonomous System Number). `blocklist-format` should be set to `asn` in that case.

### Examples

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

Response blocklist that is cached on local disk for faster startup. By default, logs will contain the source (in this case the URL) of a match, but different name can be specified with `name`.

```toml
[groups.cloudflare-blocklist]
type              = "response-blocklist-ip"
resolvers         = ["cloudflare-dot"]
blocklist-refresh = 86400
blocklist-source  = [
  {name = "my-block-list", source = "https://host/block.cidr.txt", cache-dir="/var/cache/routedns"},
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

Response blocklist based on ASN of the IP. The ASNs of the organizations to be blocked must be provided as an array of string.

```toml
[groups.cloudflare-blocklist]
type                = "response-blocklist-ip"
resolvers           = ["cloudflare-dot"]
blocklist-format    = "asn"
blocklist           = [
  "15169", # Google
]
```

Example config files: [response-blocklist-ip.toml](../cmd/routedns/example-config/response-blocklist-ip.toml), [response-blocklist-name.toml](../cmd/routedns/example-config/response-blocklist-name.toml), [response-blocklist-ip-remote.toml](../cmd/routedns/example-config/response-blocklist-ip-remote.toml), [response-blocklist-name-remote.toml](../cmd/routedns/example-config/response-blocklist-name-remote.toml), [response-blocklist-ip-resolver.toml](../cmd/routedns/example-config/response-blocklist-ip-resolver.toml), [response-blocklist-name-resolver.toml](../cmd/routedns/example-config/response-blocklist-name-resolver.toml), [response-blocklist-geo.toml](../cmd/routedns/example-config/response-blocklist-geo.toml), [response-blocklist-asn.toml](../cmd/routedns/example-config/response-blocklist-asn.toml)

## Client Blocklist

Client blocklists match the IP of the client instead of responses. By default, a client on the blocklist will receive a REFUSED, though other responses can be configured by combining it with a `static-responder`. The same options as with [response-blocklist-ip](#response-blocklist) are supported. This includes CIDR lists, static in configuration, on local disk or remote via HTTP. Also, geo location based blocklists are supported.

### Configuration

The configuration options of client blocklists are very similar to that of [response blocklists](#response-blocklist) with the exception of the `filter` option.

Client blocklists are instantiated with `type = "client-blocklist"`.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `blocklist-resolver` - Alternative resolver for responses matching a rule, the query will be re-sent to this resolver. Optional.
- `blocklist-format` - The format the blocklist is provided in. Only used if `blocklist-source` is not provided. Values can be `cidr`, or `location`. Defaults to `cidr`.
- `blocklist-refresh` - Time interval (in seconds) in which external (remote or local) blocklists are reloaded. Optional.
- `blocklist-source` - An array of blocklists, each with `format` and `source` and optionally `name`.
- `location-db` - If location-based IP blocking is used, this specifies the GeoIP data file to load. Optional. Defaults to /usr/share/GeoIP/GeoLite2-City.mmdb
- `use-ecs` - If set to true, will use the IP address in the client's ECS record instead of the real IP. Can be used to simulate queries from other source IPs. The address should be set to the IP, not a subnet for this to work. Uses the client's real IP if no ECS record is found in the query.

### Examples

Simple client blocklists that responds with DROP to all queries from one network source

```toml
[groups.cloudflare-blocklist]
type                = "client-blocklist"
resolvers           = ["cloudflare-dot"]
blocklist           = [
  '157.240.0.0/16',
]
```

This client blocklist uses the `blocklist-resolver` option to send queries from matching clients to a resolver that drops the query.

```toml
[groups.cloudflare-blocklist]
type                = "client-blocklist"
resolvers           = ["cloudflare-dot"]
blocklist-resolver  = "drop-all"
blocklist           = [
  '157.240.0.0/16',
]

[groups.drop-all]
type = "drop"
```

Example config files: [client-blocklist.toml](../cmd/routedns/example-config/client-blocklist.toml), [client-blocklist-refused.toml](../cmd/routedns/example-config/client-blocklist-refused.toml), [client-blocklist-geo.toml](../cmd/routedns/example-config/client-blocklist-geo.toml)
