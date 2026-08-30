# Logging

Part of the [RouteDNS Configuration Guide](configuration.md).

## Syslog

The `syslog` element can be used to log requests and/or responses to local or remote syslog servers. It forwards queries un-modified to the configured resolver. It is possible to configure multiple syslog loggers in different places. For example a logger could be configured to log and forward queries for domains on a blocklist, or behind a router.

### Configuration

To enable syslog, add an element with `type = "syslog"` in the groups section of the configuration.

Options:

- `resolvers` - Array of upstream resolvers, only one is supported.
- `network` - Network protocol. `udp`, `tcp` or `unix`. Defaults to `unix`.
- `address` - Remote syslog server address and port. For example `192.168.0.1:514`
- `priority` - Syslog priority. Possible values: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`
- `tag` - Syslog tag. Defaults to the program name.
- `log-request` - Enable logging of requests. Default `false`.
- `log-response` - Enable logging of responses. Default `false`.
- `verbose` - Log all answers, not just the types that match the query. Default `false`.

### Examples

```toml
[groups.cloudflare-logged]
type = "syslog"
resolvers = ["cloudflare-dot"]
network = "udp"
address = "192.168.0.1:514"
priority = "info"
tag = "routedns"
log-request = true
log-response = true
```

Example config files: [syslog.toml](../cmd/routedns/example-config/syslog.toml)

## Query Log

The `query-log` element logs all DNS query details, including time, client IP, DNS question name, class and type. Logs can be written to a file or STDOUT.

### Configuration

To enable query-logging, add an element with `type = "query-log"` in the groups section of the configuration.

Options:

- `output-file` - Name of the file to write logs to, leave blank for STDOUT. Logs are appended to the file and there is no rotation. When running under the systemd unit shipped with the packages, use a path under `/var/log/routedns`; see [Writable Paths](overview.md#writable-paths).
- `output-format` - Output format. Defaults to "text".

### Examples

```toml
[groups.query-log]
type   = "query-log"
resolvers = ["cloudflare-dot"]
output-file = "/var/log/routedns/query.log"
output-format = "text"
```

Example config files: [syslog.toml](../cmd/routedns/example-config/query-log.toml)
