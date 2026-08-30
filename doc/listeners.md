# Listeners

Part of the [RouteDNS Configuration Guide](configuration.md).

Listeners are query receivers that form the start of a query pipeline. Queries received by a listener are then forwarded to routers, groups, or to resolvers directly. Several DNS protocols are supported.

While nothing in the configuration references a listener (since it's the first element in a pipeline), it still requires a name that is defined like so `[listeners.NAME]`.

Common options for all listeners:

- `address` - Listen address.
- `protocol` - The DNS protocol used to receive queries, can be `udp`, `tcp`, `dot`, `doh`, `doq`, `dtls`, `odoh` or `admin`.
- `ip-version` - IP version (4 or 6) to use for the listener. Optional, defaults to both. Only applies to the plain DNS and DoT listeners; the protocol sections below say which.
- `resolver` - Name/identifier of the next element in the pipeline. Can be a router, group, modifier or resolver.
- `allowed-net` - Array of network addresses that are allowed to send queries to this listener, in CIDR notation, such as `["192.167.1.0/24", "::1/128"]`. If not set, no filter is applied, all clients can send queries.
- `netns` - Linux network namespace for the listening socket. Can be a name (looked up in `/var/run/netns/`) or an absolute path (e.g. `/proc/PID/ns/net`). Optional, Linux only. See [Network Namespace Support](resolvers.md#network-namespace-support).
- `xsocket` - Path to an `xsocket-server` Unix socket. The listening socket is created in that server's network namespace without requiring `CAP_SYS_ADMIN`. Mutually exclusive with `netns`. Not supported for `dtls` listeners (use `netns` instead). Optional, Linux only. See [Network Namespace Support](resolvers.md#network-namespace-support).
- `fwmark` - Linux firewall mark (`SO_MARK`) to set on the listening socket. Used for netfilter matching and policy routing. Optional, Linux only, integer. See [Firewall Mark and Interface Binding](resolvers.md#firewall-mark-and-interface-binding).
- `bind-if` - Bind the listening socket to a specific network interface (`SO_BINDTODEVICE`). Useful for VRFs or restricting a listener to one interface. Optional, Linux only. See [Firewall Mark and Interface Binding](resolvers.md#firewall-mark-and-interface-binding).

Secure listeners, such as DNS-over-TLS, DNS-over-HTTPS, DNS-over-DTLS, DNS-over-QUIC and Admin support additional options to configure certificates, keys and peer validation.

- `server-crt` - Server certificate file. Required.
- `server-key` - Server key file. Required.
- `ca` - CA to validate client certificates. Optional, but required when `mutual-tls` is enabled.
- `mutual-tls` - Requires clients to send valid (as per `ca` option) certificates before establishing a connection. Optional. When enabled, `ca` must be set; the listener will refuse to start otherwise (to avoid silently trusting the operating system's CA store for client authentication).

The DNS-over-HTTPS listener also accepts the client IP address from trusted reverse proxies in a particular subnet. X-Forwarded-For headers are only used if they are provided from this subnet.

- `trusted-proxy` - CIDR address of trusted reverse proxy. Optional.

## Plain DNS

Regular (insecure) DNS protocol over port 53, UDP and TCP. Setting `protocol` to `udp` will start a UDP listener, and `tcp` starts a TCP listener. In many cases both are present in a configuration if RouteDNS is used to provide DNS to local services over the loopback device.

### Configuration

Plain DNS listeners are instantiated with `protocol = "udp"` or `protocol = "tcp"` in the listeners section. The port defaults to `53` when the address does not carry one.

Options:

- All [common listener options](#listeners).
- `ip-version` - Restrict the listener to IPv4 (`4`) or IPv6 (`6`). Optional, defaults to both.

The TLS options do not apply, this protocol is un-encrypted.

### Examples

```toml
[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "router1"

[listeners.local-tcp]
address = "127.0.0.1:53"
protocol = "tcp"
resolver = "router1"
```

## DNS-over-TLS

DNS protocol using a TLS connection (DoT) as per [RFC7858](https://tools.ietf.org/html/rfc7858).

### Configuration

DoT listeners are instantiated with `protocol = "dot"` in the listeners section. The port defaults to `853` when the address does not carry one.

Options:

- All [common listener options](#listeners).
- `server-crt`, `server-key`, `ca`, `mutual-tls` - [TLS options](#listeners) for the server certificate and client validation. `server-crt` and `server-key` are required.
- `ip-version` - Restrict the listener to IPv4 (`4`) or IPv6 (`6`). Optional, defaults to both.

### Examples

DoT listener accepting any client. Does not require client certificates and does not validate client certificates with a CA.

```toml
[listeners.local-dot]
address = ":853"
protocol = "dot"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
```

DoT listener enforcing mTLS and verifying client certificates with a CA.

```toml
[listeners.local-dot]
address = ":853"
protocol = "dot"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
ca = "/path/to/ca.crt"
mutual-tls = true
```

Example config files: [mutual-tls-dot-server.toml](../cmd/routedns/example-config/mutual-tls-dot-server.toml)

## DNS-over-HTTPS

DNS using the HTTPS protocol as per [RFC8484](https://tools.ietf.org/html/rfc8484).

### Configuration

DoH listeners are instantiated with `protocol = "doh"` in the listeners section. The port defaults to `443`, or `1443` with QUIC transport, when the address does not carry one.

Options:

- All [common listener options](#listeners).
- `server-crt`, `server-key`, `ca`, `mutual-tls` - [TLS options](#listeners) for the server certificate and client validation. Required unless `no-tls` is set.
- `transport` - `"tcp"` (default) for HTTP/2 over TCP, or `"quic"` to run DoH over QUIC.
- `no-tls` - Serve plain HTTP rather than HTTPS. For testing, or behind a reverse proxy that terminates TLS already. Not supported with `transport = "quic"`, the listener refuses to start. Optional, defaults to false.
- `trusted-proxy` - CIDR of a reverse proxy whose `X-Forwarded-For` header is trusted to carry the real client address. Given under a `frontend` key, see the example below. Optional.

`ip-version` has no effect on this listener.

### Examples

DoH listener accepting queries from any client.

```toml
[listeners.local-doh]
address = ":443"
protocol = "doh"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
```

DoH over QUIC listener.

```toml
[listeners.local-doh-quic]
address = ":1443"
protocol = "doh"
transport = "quic"
resolver = "cloudflare-dot"
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

DoH behind a reverse proxy. Clients are expected to connect to a reverse proxy in this subnet, which will provide their IP address in the X-Forwarded-For header. RouteDNS will trust this header from proxies in the subnet listed in `trusted-proxy`

```toml
[listeners.local-doh]
address = ":443"
protocol = "doh"
resolver = "cloudflare-dot"
server-crt = "/path/to/server.crt"
server-key = "/path/to/server.key"
frontend = { trusted-proxy = "192.168.1.0/24" }
```

Example config files: [mutual-tls-doh-server.toml](../cmd/routedns/example-config/mutual-tls-doh-server.toml), [doh-quic-server.toml](../cmd/routedns/example-config/doh-quic-server.toml), [doh-behind-proxy.toml](../cmd/routedns/example-config/doh-behind-proxy.toml), [doh-no-tls.toml](../cmd/routedns/example-config/doh-no-tls.toml)

## Oblivious DNS (ODoH)

ODoH ([RFC9230](https://datatracker.ietf.org/doc/rfc9230/)) improves the privacy of **clients** by encrypting queries for a **target** DNS server and sending them through a **proxy**, so that neither the target nor the proxy sees the query content and the source IP of the client at the same time. Listeners are configured with `protocol = "odoh"` and can act as the target, the proxy, or both. See the [ODoH resolver](resolvers.md#oblivious-dns-odoh-resolver) for the client side.

By default the ODoH listener listens on `/proxy` and `/dns-query`. Additionally, it will host its HPKE config under `/.well-known/odohconfigs`. If `odoh-mode = "proxy"` is set, it will only listen and handle ODoH proxy requests on `/proxy`. If set to target the listener will only handle the ODoH queries on `/dns-query`.

### Configuration

ODoH listeners are instantiated with `protocol = "odoh"` in the listeners section. The port defaults to `443` when the address does not carry one.

Options:

- All [common listener options](#listeners).
- `server-crt`, `server-key`, `ca`, `mutual-tls` - [TLS options](#listeners) for the server certificate and client validation. `server-crt` and `server-key` are required.
- `key-seed` - 16 byte hex seed the HPKE keypair is generated from, for example from `openssl rand -hex 16`. Not needed in proxy mode. In target mode, a new random key is generated on every launch if this is not set, which invalidates any config clients have cached.
- `odoh-mode` - `"target"` (default), `"proxy"` or `"dual"`. Determines which of the two paths the listener serves.
- `allow-doh` - Also answer plain DoH queries on `/dns-query` using the same resolver. Ignored in proxy mode. Optional, defaults to false.

`ip-version` has no effect on this listener.

### Examples

```toml
[listeners.local-odoh]
address = ":443"
protocol = "odoh"
resolver = "cloudflare-dot"

# The key seed is used to generate the HPKE keypair.
key-seed = "414dd55667a0cdff72dfbbd8515a9e0a"
# odoh-mode allowed values are "dual", "proxy" or "target". If not set (default), target mode is enabled and proxy requests are not handled.
odoh-mode  = "target"

# If enabled, the listener will also respond to regular DoH queries using the same resolver. When not set or false, DoH queries are ignored. Has no effect if odoh-mode is set to proxy
allow-doh = true

# TLS information
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

Example config files: [odoh-listener.toml](../cmd/routedns/example-config/odoh-listener.toml)

## DNS-over-DTLS

Similar to DoT, but uses a DTLS (UDP) connection as transport as per [RFC8094](https://tools.ietf.org/html/rfc8094).

### Configuration

DTLS listeners are instantiated with `protocol = "dtls"` in the listeners section. The port defaults to `853` when the address does not carry one.

Options:

- All [common listener options](#listeners), except `xsocket` which is not supported for this protocol. Use `netns` instead.
- `server-crt`, `server-key`, `ca`, `mutual-tls` - [TLS options](#listeners) for the server certificate and client validation. `server-crt` and `server-key` are required. An EC certificate is normally used here.

`ip-version` has no effect on this listener.

### Examples

DTLS listener.

```toml
[listeners.local-dtls]
address = ":853"
protocol = "dtls"
resolver = "cloudflare-dot"
server-crt = "example-config/server-ec.crt"
server-key = "example-config/server-ec.key"
```

Example config files: [dtls-server.toml](../cmd/routedns/example-config/dtls-server.toml)

## DNS-over-QUIC

Similar to DoT, but uses a QUIC connection as transport as per [RFC9250](https://datatracker.ietf.org/doc/rfc9250/). Configured with `protocol = "doq"`. Note that this is different from DoH over QUIC. See [DNS-over-HTTPS](#dns-over-https) for how to configure this.

Note: Support for the QUIC protocol is still experimental. For the purpose of DNS, there are two implementations, DNS-over-QUIC ([RFC9250](https://datatracker.ietf.org/doc/rfc9250/)) as well as DNS-over-HTTPS using QUIC. Both methods are supported by RouteDNS, client and server implementations.

### Configuration

DoQ listeners are instantiated with `protocol = "doq"` in the listeners section. The port defaults to `8853` when the address does not carry one.

Options:

- All [common listener options](#listeners).
- `server-crt`, `server-key`, `ca`, `mutual-tls` - [TLS options](#listeners) for the server certificate and client validation. `server-crt` and `server-key` are required.

`ip-version` has no effect on this listener.

### Examples

DoQ listener accepting queries from all clients.

```toml
[listeners.local-doq]
address = ":8853"
protocol = "doq"
resolver = "cloudflare-dot"
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

Example config files: [doq-listener.toml](../cmd/routedns/example-config/doq-listener.toml)

## Admin

The Admin listener provides metrics on RouteDNS usage and performance at https://{address}/routedns/vars/ in [expvar](https://pkg.go.dev/expvar) format. These metrics can be exported to be usable by Prometheus using [prometheus-expvar-exporter](https://github.com/albertito/prometheus-expvar-exporter).

### Configuration

The admin listener is instantiated with `protocol = "admin"` in the listeners section. It serves metrics rather than answering queries, so it is the one listener that takes no `resolver`, and no default port is applied to its address.

Options:

- All [common listener options](#listeners), except `resolver`, which is not used.
- `server-crt`, `server-key`, `ca`, `mutual-tls` - [TLS options](#listeners) for the server certificate and client validation.
- `transport` - `"tcp"` (default) or `"quic"`.

`ip-version` has no effect on this listener.

### Examples

```toml
[listeners.local-admin]
address = "127.0.0.7:443"
protocol = "admin"
server-crt = "example-config/server.crt"
server-key = "example-config/server.key"
```

Example config files: [admin.toml](../cmd/routedns/example-config/admin.toml), [prometheus-exporter](../cmd/routedns/example-config/prometheus-exporter/)
