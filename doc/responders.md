# Responders

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | **Responders** | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | [Resolvers](resolvers.md) | [Templates](templates.md)

## Static responder

`type = "static-responder"`

A static responder can be used to terminate every query made to it with a fixed answer. The answer can contain Answer, NS, and Extra records with a configurable RCode. Static responders are useful in combination with routers to build walled-gardens or blocklists providing more control over the response. The individual records in the response are defined in zone-file format. The default TTL is 1h unless given in the record.

### Configuration

Static responders are instantiated with `type = "static-responder"` in the groups section of the configuration.

Options:

- `rcode` - Response code: 0 = NOERROR, 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, ... See [rfc2929#section-2.3](https://tools.ietf.org/html/rfc2929#section-2.3) for a more complete list. Defaults to 0 (No Error).
- `answer` - Array of strings, each one representing a line in zone-file format. Forms the content of the Answer records in the response. The name in all answer records is replaced with the name in the query to create a match.
- `ns` - Array of strings, each one representing a line in zone-file format. Forms the content of the Authority records in the response.
- `extra` - Array of strings, each one representing a line in zone-file format.  Forms the content of the Additional records in the response.
- `truncate` - when true, TC Bit is set in response. Default is false.
- `edns0-ede` - Optional, include an extended error code in the response if it's blocked. Only used when the response is blocked, not when it's spoofed. The value is a struct with two keys, `code` (number) and `text` (string). Possible values for `code` are defined in [rfc8914](https://datatracker.ietf.org/doc/html/rfc8914) while `text` can carry additional information that is displayed by `dig` for example. The `text` value is a template that has access to a number of fields of query to allow customizing the response based on data in the query. See [Templates](templates.md#templates) for details. Simple placeholders in `text` would be `{{ .Question }}` for the question in the query or `{{ .ID }}` to be replaced with the query ID.

Note:

The default TTL of all records is 3600 unless provided in the configuration. To set the TTL in the answer, provide a placeholder for the name like so: `". 86400 IN A 1.2.3.4"`. Starting the line with the TTL value will not work.

### Examples

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
[groups.static-servfail]
type  = "static-responder"
rcode = 2 # SERVFAIL
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

Return an empty answer with TC (Truncate) bit set so the DNS client is instructed to retry the query using TCP instead of UDP.

```toml
[groups.static-truncate]
type     = "static-responder"
rcode    = 0 # NOERROR
truncate = True
```

Return an extended error code explaining why a query was blocked.

```toml
[groups.static]
type  = "static-responder"
edns0-ede = {code = 15, text = "Blocked because reasons"}
```

Example config files: [walled-garden.toml](../cmd/routedns/example-config/walled-garden.toml), [rfc8482.toml](../cmd/routedns/example-config/rfc8482.toml), [static-extended-error.toml](../cmd/routedns/example-config/static-extended-error.toml)

## Static Template Responder

`type = "static-template"`

A static template responder operates similarly to a [Static Responder](#static-responder) with the main difference being that the records configured are templates, meaning they can contain placeholders which can refer to data in the query, such as the question. Based on the values in the question, the template can manipulate the response. Templates can contain more complex operations such as string splitting, replacing etc.

### Configuration

A static template responder is instantiated with `type = "static-template"` in the groups section of the configuration.

Options:

- The same options as the [Static Responder](#static-responder). The difference is that `answer`, `ns` and `extra` are treated as [templates](templates.md#templates).

### Examples

A fixed responder that can respond to queries like `192.168.1.12.rebind.` by stripping the `.rebind.` suffix and treating the remaining string as IP. Note that the template in this case has to produce a valid IP or it will fail. To ensure the queries reaching this responder are always valid it may be best to combine with a router or blocklist in front of it.

```toml
[groups.static]
type   = "static-template"
answer = [
    '{{ .Question }} IN A {{ trimSuffix .Question ".rebind."}}'
]
```

Same as above but converts `192-168-1-12.rebind` into an IP.

```toml
[groups.static]
type   = "static-template"
answer = [
  '{{ .Question }} {{ .QuestionClass }} {{ .QuestionType }} {{ replaceAll ( index ( split .Question "." ) 0 ) "-" "." }}'
]
```

Return an extended error code explaining why a query was blocked.

```toml
[groups.static]
type   = "static-template"
edns0-ede = {code = 15, text = '{{ .Question }} is banned!'}
```

Example config files: [static-template.toml](../cmd/routedns/example-config/static-template.toml), [static-template-error.toml](../cmd/routedns/example-config/static-template-error.toml)

## Drop

`type = "drop"`

Terminates a pipeline by dropping the request. Typically used with blocklists to abort queries that match block rules. UDP and TCP listeners close the connection without replying, while HTTP listeners will reply with an HTTP error.

### Configuration

A drop group is instantiated with `type = "drop"` in the groups section of the configuration.

Options:

- None. A drop group terminates the pipeline, so it takes no `resolvers` either.

### Examples

Client blocklist that drops requests from clients on the blocklist.

```toml
[groups.cloudflare-blocklist]
type                = "client-blocklist"
resolvers           = ["cloudflare-dot"]
blocklist-resolver  = "drop" # Any match is sent to a resolver that drops the query
blocklist           = [
  '157.240.0.0/16',
]

[groups.drop]
type = "drop"

```

Example config files: [client-blocklist-drop.toml](../cmd/routedns/example-config/client-blocklist-drop.toml)
