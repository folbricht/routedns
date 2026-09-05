# Resolvers

[Guide index](configuration.md) | [Overview](overview.md) | [Listeners](listeners.md) | [Routing](routing.md) | [Blocklists](blocklists.md) | [Caching and Performance](caching.md) | [Failover and Load Balancing](groups.md) | [Modifiers](modifiers.md) | [Responders](responders.md) | [Lua Scripting](scripting.md) | [DNSSEC and Rate Limiting](security.md) | [Logging](observability.md) | **Resolvers** | [Templates](templates.md)

**On this page:** [Bootstrapping](#bootstrapping) | [Plain DNS Resolver](#plain-dns-resolver) | [DNS-over-TLS Resolver](#dns-over-tls-resolver) | [DNS-over-HTTPS Resolver](#dns-over-https-resolver) | [Oblivious DNS (ODoH) Resolver](#oblivious-dns-odoh-resolver) | [DNS-over-DTLS Resolver](#dns-over-dtls-resolver) | [DNS-over-QUIC Resolver](#dns-over-quic-resolver) | [Bootstrap Resolver](#bootstrap-resolver) | [SOCKS5 Proxy Support](#socks5-proxy-support) | [Network Namespace Support](#network-namespace-support) | [Firewall Mark and Interface Binding](#firewall-mark-and-interface-binding)

Resolvers forward queries to other DNS servers over the network and typically represent the end of one or many processing pipelines. Resolvers encode every query that is passed from listeners, modifiers, routers etc and send them to a DNS server without further processing. Like with other elements in the pipeline, resolvers require a unique identifier to reference them from other elements. The following protocols are supported:

- udp - Plain (un-encrypted) DNS over UDP
- tcp - Plain (un-encrypted) DNS over TCP
- dot - DNS-over-TLS
- doh - DNS-over-HTTP (including DoH over QUIC)
- doq - DNS-over-QUIC
- dtls - DNS-over-DTLS
- odoh - Oblivious DNS-over-HTTPS

Resolvers are defined in the configuration like so `[resolvers.NAME]` and have the following common options:

- `address` - Remote server endpoint and port. Can be IP or hostname, or a full URL depending on the protocol. See the [Bootstrapping](#bootstrapping) on how to handle hostnames that can't be resolved.
- `protocol` - The DNS protocol used to send queries, can be `udp`, `tcp`, `dot`, `doh`, `doq`, `dtls` or `odoh`.
- `bootstrap-address` - Use this IP address if the name in `address` can't be resolved. Using the IP in `address` directly may not work when TLS/certificates are used by the server. Has no effect on plain DNS resolvers.
- `local-address` - IP of the local interface to use for outgoing connections. The address is automatically chosen if this option is left blank.
- `local-address-v4` - IPv4 address of the local interface to use when connecting to IPv4 targets. Takes priority over `local-address` for IPv4 connections.
- `local-address-v6` - IPv6 address of the local interface to use when connecting to IPv6 targets. Takes priority over `local-address` for IPv6 connections. The address must be unbracketed (e.g. `fd00::1`, not `[fd00::1]`).
- `edns0-udp-size` - If set, modifies the EDNS0 UDP size option in all queries sent upstream. Only meaningful when using UDP or DTLS resolvers. Upstream resolvers may not respect this value and apply their own limits.
- `query-timeout` - Sets the query timeout to allow. In seconds.
- `netns` - Linux network namespace for outbound connections. Can be a name (looked up in `/var/run/netns/`) or an absolute path (e.g. `/proc/PID/ns/net`). Optional, Linux only. See [Network Namespace Support](#network-namespace-support).
- `xsocket` - Path to an `xsocket-server` Unix socket. Outbound connections are made through a socket created in that server's network namespace without requiring `CAP_SYS_ADMIN`. Mutually exclusive with `netns`. For SOCKS5-proxied resolvers it is the connection to the proxy that is made in the target namespace. Optional, Linux only. See [Network Namespace Support](#network-namespace-support).
- `fwmark` - Linux firewall mark (`SO_MARK`) to set on outbound connections. Used for netfilter matching and policy routing. Optional, Linux only, integer. See [Firewall Mark and Interface Binding](#firewall-mark-and-interface-binding).
- `bind-if` - Bind outbound connections to a specific network interface (`SO_BINDTODEVICE`). Useful for VRFs or forcing upstream traffic out of one interface. Optional, Linux only. See [Firewall Mark and Interface Binding](#firewall-mark-and-interface-binding).

Secure resolvers such as DoT, DoH, or DoQ offer additional options to configure the TLS connections.

- `client-crt` - Client certificate file.
- `client-key` - Client certificate key file
- `ca` - CA certificate to validate server certificates.
- `server-name` - Name of the certificate presented by the server if it does not match the name in the endpoint address.

Examples:

A simple DoT resolver.

```toml
[resolvers.cloudflare-dot]
address = "1.1.1.1:853"
protocol = "dot"
```

DoT resolver supporting mutual-TLS, providing a certificate and key, plus validating the remote cert with a CA certificate.

```toml
[resolvers.my-mutual-tls]
address = "myserver:853"
protocol = "dot"
ca = "/path/to/my-ca.pem"
client-key = "/path/to/my-key.pem"
client-crt = "/path/to/my-crt.pem"
```

UDP resolver with dual-stack local addresses. When the upstream resolves to an IPv4 address, `local-address-v4` is used as the source; when it resolves to IPv6, `local-address-v6` is used.

```toml
[resolvers.quad9]
address = "9.9.9.9:53"
protocol = "udp"
local-address-v4 = "10.96.0.23"
local-address-v6 = "fd54:20a4:d33b:b10c::1"
```

A list of well-known public DNS services can be found [here](../cmd/routedns/example-config/well-known.toml)

## Bootstrapping

When upstream services are configured using their hostnames, RouteDNS will first have to resolve the hostname of the service before establishing a secure connection with it. There are a couple of potential issues with this:

- The initial lookup is using the OS' resolver which could be using plain/un-encrypted DNS. This may not be desirable or even fail if no other DNS is available.
- The service does not support querying it by IP directly and a hostname is needed. Google for example does not support DoH using `https://8.8.8.8/dns-query`. The endpoint has to be configured as `https://dns.google/dns-query`.

To solve these issues, it is possible to add a bootstrap IP address to the resolver config or to use a [bootstrap resolver](#bootstrap-resolver). This will use the IP to connect to the service without first having to perform a lookup while still preserving the DoH URL or DoT hostname for the TLS handshake. The `bootstrap-address` option is available on both, DoT and DoH resolvers.

```toml
[resolvers.google-doh-post-bootstrap]
address = "https://dns.google/dns-query"
protocol = "doh"
bootstrap-address = "8.8.8.8"
```

## Plain DNS Resolver

`protocol = "udp"` or `protocol = "tcp"`

Plain, un-encrypted DNS protocol clients for UDP or TCP. Note that UDP responses can be truncated so it is common to use it in combination with a [truncate-retry](caching.md#retrying-truncated-responses) group to define a fallback.

### Configuration

Plain DNS resolvers are instantiated with `protocol = "udp"` or `protocol = "tcp"` in the resolvers section. The port defaults to `53` when the address does not carry one.

Options:

- All [common resolver options](#resolvers) except `bootstrap-address`, which has no effect here since no TLS handshake needs a name.
- `edns0-udp-size` - Set the EDNS0 UDP size in queries sent upstream. Optional, and only meaningful for `udp`.
- `socks5-address`, `socks5-username`, `socks5-password`, `socks5-resolve-local` - Connect through a [SOCKS5 proxy](#socks5-proxy-support). Optional.

The TLS options do not apply, this protocol is un-encrypted.

### Examples

```toml
[resolvers.google-udp-8-8-8-8]
address = "8.8.8.8:53"
protocol = "udp"

[resolvers.cloudflare-tcp]
address = "1.1.1.1:53"
protocol = "tcp"
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml), [truncate-retry.toml](../cmd/routedns/example-config/truncate-retry.toml)

## DNS-over-TLS Resolver

`protocol = "dot"`

DNS protocol using a TLS connection (DoT) as per [RFC7858](https://tools.ietf.org/html/rfc7858).

### Configuration

DoT resolvers are instantiated with `protocol = "dot"` in the resolvers section. The port defaults to `853` when the address does not carry one.

Options:

- All [common resolver options](#resolvers).
- `ca`, `client-crt`, `client-key`, `server-name` - [TLS options](#resolvers) for validating the server and presenting a client certificate.
- `socks5-address`, `socks5-username`, `socks5-password`, `socks5-resolve-local` - Connect through a [SOCKS5 proxy](#socks5-proxy-support). Optional.

`edns0-udp-size` does not apply to this protocol.

### Examples

Simple DoT resolver using a well-known service.

```toml
[resolvers.cloudflare-dot-1-1-1-1]
address = "1.1.1.1:853"
protocol = "dot"
```

DoT resolver trusting only a specific CA.

```toml
[resolvers.cloudflare-dot-with-ca]
address = "1.1.1.1:853"
protocol = "dot"
ca = "/path/to/DigiCertECCSecureServerCA.pem"
```

DoT resolver using mTLS with a server that expects a client certificate

```toml
[resolvers.my-mutual-tls]
address = "myserver:853"
protocol = "dot"
ca = "/path/to/my-ca.pem"
client-key = "/path/to/my-key.pem"
client-crt = "/path/to/my-crt.pem"
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml), [family-browsing.toml](../cmd/routedns/example-config/family-browsing.toml), [simple-dot-cache.toml](../cmd/routedns/example-config/simple-dot-cache.toml)

## DNS-over-HTTPS Resolver

`protocol = "doh"`

DNS resolvers using the HTTPS protocol are configured with `protocol = "doh"`. By default, DoH uses TCP as transport, but it can also be run over QUIC (UDP) by providing the option `transport = "quic"`. DoH supports two HTTP methods, GET and POST. By default RouteDNS uses the POST method, but can be configured to use GET as well using the option `doh = { method = "GET" }`.
DoH with QUIC supports 0-RTT. The DoH resolver will try to use 0-RTT connection establishment if `transport = "quic"` and `enable-0rtt = true` are configured. Only GET requests can be sent as 0-RTT data, so with `enable-0rtt = true` the method defaults to GET when none is configured, and the address has to be a URL template containing the `{?dns}` parameter. RouteDNS fails to start if 0-RTT is enabled on a configuration that can't use it: with `transport` other than `"quic"`, with `doh = { method = "POST" }`, or with an address that isn't a URL template. Since 0-RTT data is replayable, only the opcodes RFC 9250 allows there (QUERY and NOTIFY) are sent as early data; queries with any other opcode wait for the handshake to complete.
The idle connection timeout can be configured with `doh = { idle-timeout = 60 }` (in seconds). This controls how long idle HTTP connections are kept open before being closed. For TCP transport, the default is 30 seconds. For QUIC transport, the default is determined by the quic-go library. Note that for QUIC, the actual idle timeout is the minimum of the client and server values.

### Configuration

DoH resolvers are instantiated with `protocol = "doh"` in the resolvers section. The `address` is the full endpoint URL. The port defaults to `443` when the URL does not carry one.

Options:

- All [common resolver options](#resolvers).
- `ca`, `client-crt`, `client-key`, `server-name` - [TLS options](#resolvers) for validating the server and presenting a client certificate.
- `transport` - `"tcp"` (default) for HTTP/2 over TCP, or `"quic"` to run DoH over QUIC.
- `doh` - Table of DoH-specific settings: `method` (`"POST"` default, or `"GET"`) and `idle-timeout` in seconds.
- `enable-0rtt` - Use 0-RTT connection establishment. Requires `transport = "quic"`, the GET method, and a URL template address. Optional, defaults to false.
- `socks5-address`, `socks5-username`, `socks5-password`, `socks5-resolve-local` - Connect through a [SOCKS5 proxy](#socks5-proxy-support). Optional.

`edns0-udp-size` does not apply to this protocol.

### Examples

Simple DoH resolver using the POST method.

```toml
[resolvers.cloudflare-doh-post]
address = "https://1.1.1.1/dns-query"
protocol = "doh"
```

Simple DoH resolver using the GET method.

```toml
[resolvers.cloudflare-doh-get]
address = "https://1.1.1.1/dns-query{?dns}"
protocol = "doh"
doh = { method = "GET" }
```

DoH resolver using QUIC transport.

```toml
[resolvers.cloudflare-doh-quic]
address = "https://cloudflare-dns.com/dns-query{?dns}"
protocol = "doh"
transport = "quic"
enable-0rtt = true
```

DoH resolver with extended idle timeout.

```toml
[resolvers.cloudflare-doh-long-idle]
address = "https://1.1.1.1/dns-query"
protocol = "doh"
doh = { idle-timeout = 60 }
```

Example config files: [well-known.toml](../cmd/routedns/example-config/well-known.toml), [simple-doh.toml](../cmd/routedns/example-config/simple-doh.toml), [mutual-tls-doh-client.toml](../cmd/routedns/example-config/mutual-tls-doh-client.toml)

## Oblivious DNS (ODoH) Resolver

`protocol = "odoh"`

ODoH ([RFC9230](https://datatracker.ietf.org/doc/rfc9230/)) is intended to improve privacy of **clients** by encrypting queries for a **target** DNS server while sending the query through a **proxy**. In this configuration, neither the target nor the proxy can see the query content and the source IP of the client at the same time. A client query is resolved as follows:

- If the clients target-config = "" parameter is not set, the client will automatically query the public key of the target resolver directly from the target. This is bad for the anonymity of the client and should be avoided by pre-configuring the config beforehand.
- The client then encrypts the actual query with the public key of the target. A public key of the client is embedded in the encrypted message.
- The encrypted query message is sent to the proxy, with information about which target it should be forwarded to.
- The target then encrypts the response with the client key and responds to the proxy, which then forwards the response to the client.
- The client decrypts the response it received from the proxy using its private key.

### Configuration

ODoH resolvers are instantiated with `protocol = "odoh"` in the resolvers section. The endpoint, certificate and mTLS options all describe the connection to the **proxy**; the target is reached by the proxy on the client's behalf, so it takes no certificate or bootstrap options of its own. No default port is applied to the address.

Options:

- All [common resolver options](#resolvers).
- `ca`, `client-crt`, `client-key`, `server-name` - [TLS options](#resolvers) for validating the server and presenting a client certificate. These apply to the proxy connection.
- `target` - URL of the ODoH target. Required.
- `target-config` - The target's ODoH config, as hex. Fetched from the target automatically when not set, which costs the client's anonymity for that one request, so prefer configuring it. Running with debug logging prints the fetched value so it can be copied here.
- `transport` - `"tcp"` (default) or `"quic"` for the proxy connection.
- `doh` - Table of DoH-specific settings for the proxy connection: `method` and `idle-timeout`.

`edns0-udp-size`, `enable-0rtt` and the SOCKS5 options do not apply to this protocol.

### Examples

ODoH client using Cloudflare as target. If a proxy is available, set `address` to the proxy URL. If omitted, the target is contacted directly.

```toml
[resolvers.cloudflare-odoh]
protocol = "odoh"
# Address of the oblivious DNS proxy server. If omitted, the target is used directly.
# address = "https://odoh-proxy.example.com/proxy"
# Address of the target. The hostname and path are passed to the proxy for forwarding
# of encrypted queries. No cert or bootstrap options for the target since the proxy
# connects to it on the client's behalf
target = "https://odoh.cloudflare-dns.com/dns-query"

# The ODoH config/key of the Target.
target-config = "0000000secret...."
# The ODoH config is usually hosted on the target under https://[target]/.well-known/odohconfigs
# If the target-config is not specified here, the resolver will request it automatically. Running the client with debug flags will also print the targets public key/config. This can then be copied to the config file, to avoid repeatedly fetching the key with every new launch of the client.

```

Example config files: [odoh-client.toml](../cmd/routedns/example-config/odoh-client.toml)

## DNS-over-DTLS Resolver

`protocol = "dtls"`

Similar to DoT, but uses a DTLS (UDP) connection as transport as per [RFC8094](https://tools.ietf.org/html/rfc8094).

### Configuration

DTLS resolvers are instantiated with `protocol = "dtls"` in the resolvers section. The port defaults to `853` when the address does not carry one.

Options:

- All [common resolver options](#resolvers).
- `ca`, `client-crt`, `client-key` - [TLS options](#resolvers) for validating the server and presenting a client certificate. `server-name` is not supported for DTLS.
- `edns0-udp-size` - Set the EDNS0 UDP size in queries sent upstream. Optional.

`enable-0rtt` and the SOCKS5 options do not apply to this protocol.

### Examples

DTLS resolver trusting a specific server certificate and setting a bootstrap address to avoid looking up the server IP at startup.

```toml
[resolvers.local-dtls]
address = "server.acme.test:853"
protocol = "dtls"
ca = "example-config/server-ec.crt"
bootstrap-address = "127.0.0.1"
```

Example config files: [dtls-client.toml](../cmd/routedns/example-config/dtls-client.toml)

## DNS-over-QUIC Resolver

`protocol = "doq"`

Similar to DoT, but uses a QUIC connection as transport as per [RFC9250](https://datatracker.ietf.org/doc/rfc9250/). Configured with `protocol = "doq"`. Note that this is different from DoH over QUIC. See [DNS-over-HTTPS](#dns-over-https-resolver) for how to configure this.
The DoQ resolver will try to use 0-RTT connection establishment if `enable-0rtt = true` is configured. Since 0-RTT data is replayable, only the opcodes RFC 9250 allows there (QUERY and NOTIFY) are sent as early data; queries with any other opcode wait for the handshake to complete.

### Configuration

DoQ resolvers are instantiated with `protocol = "doq"` in the resolvers section. The port defaults to `8853` when the address does not carry one.

Options:

- All [common resolver options](#resolvers).
- `ca`, `client-crt`, `client-key`, `server-name` - [TLS options](#resolvers) for validating the server and presenting a client certificate.
- `enable-0rtt` - Use 0-RTT connection establishment. Optional, defaults to false.

`edns0-udp-size` and the SOCKS5 options do not apply to this protocol.

### Examples

```toml
[resolvers.local-doq]
address = "server.acme.test:8853"
protocol = "doq"
ca = "example-config/server.crt"
bootstrap-address = "127.0.0.1"
enable-0rtt = true
```

Example config files: [doq-client.toml](../cmd/routedns/example-config/doq-client.toml)

## Bootstrap Resolver

`[bootstrap-resolver]`

Some configurations contain references to external resources by hostname. For example remote blocklists or resolvers. For those configurations to be valid, RouteDNS needs to be able to resolve those names at startup. If RouteDNS is the only service providing name resolution, this would fail. A bootstrap resolver allows the config to provide a resolver that is used to lookup such hostnames from the RouteDNS process itself. Bootstrap resolvers support the same protocols and options as regular resolvers.
Note: Resolvers (including the bootstrap resolver itself) also support a `bootstrap-address` property that sets the IP directly and bypasses the bootstrap resolver.

### Configuration

The bootstrap resolver is defined in a top-level `[bootstrap-resolver]` table rather than under `resolvers`, since nothing references it by name. There can be only one.

Options:

- The same options as the resolver protocol it uses, see the protocol sections above.

### Examples

Use Cloudflare DoT to resolve all hostnames in the configuration.

```toml
[bootstrap-resolver]
address = "1.1.1.1:853"
protocol = "dot"
```

Example config files: [bootstrap-resolver.toml](../cmd/routedns/example-config/bootstrap-resolver.toml), [use-case-6.toml](../cmd/routedns/example-config/use-case-6.toml)

## SOCKS5 Proxy Support

Several resolver types support connecting to upstream servers through a SOCKS5 proxy. This includes:

- [Plain DNS](#plain-dns-resolver)
- [DNS-over-TLS](#dns-over-tls-resolver)
- [DNS-over-HTTPS](#dns-over-https-resolver)

If SOCKS5 is available, the following options can be used to configure it:

Options:

- `socks5-address` - SOCKS5 server address, including port.
- `socks5-username` - SOCKS5 server username.
- `socks5-password` - SOCKS5 server password.
- `socks5-resolve-local` - Experimental: Resolve the upstream DNS server name locally before connecting through the proxy.

### Examples

```toml
[resolvers.cloudflare-doh]
address = "https://cloudflare-dns.com/dns-query"
protocol = "doh"
socks5-address = "1.2.3.4:1080"
socks5-username = "test"
socks5-password = "test"
```

## Network Namespace Support

On Linux, listeners and resolvers can be assigned to different network namespaces using the `netns` option. This allows RouteDNS to listen for queries in one namespace (e.g. a container) and resolve them via another (e.g. the host), without requiring iptables rules or veth forwarding.

The `netns` value can be either:

- A **name** — looked up in `/var/run/netns/` (as created by `ip netns add`)
- An **absolute path** — e.g. `/proc/PID/ns/net` to reference another process's namespace

The option is supported on all listener protocols (UDP, TCP, DoT, DoH, DoQ, DTLS, Admin) and all resolver protocols (UDP, TCP, DoT, DoH, DoQ, DTLS, ODoH). On non-Linux platforms, configuring `netns` returns an error.

Listeners bound to a named namespace are supervised: the listener starts when the namespace appears and stops when it is removed, so namespaces can come and go while RouteDNS runs. This requires `/var/run/netns` to exist when RouteDNS starts; the directory is created by the first `ip netns add` after boot. If RouteDNS starts before that, the listener is disabled with an error. To start RouteDNS independent of namespace creation order, create the directory beforehand, e.g. with `ExecStartPre=+mkdir -p /run/netns` in a systemd unit.

Options:

- `netns` - Namespace name or absolute path. Available on listeners and resolvers. Mutually exclusive with `xsocket`.
- `xsocket` - Path to an `xsocket-server` Unix socket, see below. Available on listeners and resolvers, except `dtls` listeners.

### Examples

Listen in a container namespace, resolve in the host namespace:

```toml
[resolvers.host-upstream]
address = "8.8.8.8:53"
protocol = "udp"
netns = "/proc/1/ns/net"

[listeners.container-udp]
address = "10.0.0.2:53"
protocol = "udp"
resolver = "host-upstream"
netns = "container"
```

Example config files: [netns.toml](../cmd/routedns/example-config/netns.toml)

### Without elevated privileges: xsocket

The `netns` option uses `setns(2)`, which requires the RouteDNS process to hold `CAP_SYS_ADMIN`. The `xsocket` option is an alternative that avoids this. It relies on [xsocket](https://github.com/koro666/xsocket): a small `xsocket-server` runs inside the target namespace and listens on a Unix socket. RouteDNS connects to that socket, asks the server to create a socket in its namespace, and receives the file descriptor back over the Unix socket (`SCM_RIGHTS`). RouteDNS then binds or connects that descriptor itself - so RouteDNS itself needs no elevated privileges at all, while still listening in and connecting to any number of namespaces.

Placing `xsocket-server` inside the target namespace usually requires privilege to set up (e.g. `ip netns exec`, which needs root), but the server process itself can drop to an unprivileged user once there: creating sockets and passing file descriptors needs no capabilities. It only needs to retain privileges - e.g. `CAP_NET_ADMIN`/`CAP_NET_RAW`, possibly via an `LD_PRELOAD` shim - if it must apply privileged socket options such as firewall marks (`fwmark`) itself.

RouteDNS ships with a compatible server built in: `routedns fd-server <socket-path>` runs an fd-server that can be used in place of `xsocket-server`, so no separate binary needs to be deployed. By default it only hands out IPv4/IPv6 TCP and UDP sockets - everything RouteDNS itself requests - and refuses anything else with `EPERM`; the `--unrestricted` flag lifts this limit for other xsocket clients. The `--mode` flag sets the permissions on the Unix socket (octal, e.g. `--mode 0660`). Each request is logged together with the pid/uid/gid of the requesting process (`SO_PEERCRED`), identifying where a connection over the Unix socket came from.

```text
ip netns exec ns1 sudo -u routedns -- routedns fd-server --mode 0660 /var/tmp/xsocket/ns1
```

The `xsocket` value is the path to the server's Unix socket. A leading `@` denotes an abstract socket (no filesystem entry), e.g. `xsocket = "@xsocket-ns1"`. The same applies to the `fd-server` sub-command.

```toml
[resolvers.res]
address = "9.9.9.9:53"
protocol = "udp"
xsocket = "/var/tmp/xsocket/ns1"

[listeners.local-udp]
address = "[::]:1053"
protocol = "udp"
resolver = "res"
xsocket = "/var/tmp/xsocket/ns2"
```

Notes and limitations:

- `xsocket` and `netns` are mutually exclusive on the same component.
- Security boundary: anyone who can connect to the `xsocket-server`'s Unix socket can obtain sockets in its namespace. Access is controlled entirely by filesystem ownership, permissions and ACLs on the socket (and its parent directory) - set these up restrictively. Abstract sockets (`@name`) have no filesystem entry and so cannot be permission-controlled; they are reachable by any process in the server's network namespace. Prefer a pathname socket with restrictive permissions when access control matters.
- Upstream resolver addresses are resolved in RouteDNS's own namespace; prefer giving them as IP addresses.
- `fwmark` and `bind-if` still require `CAP_NET_ADMIN` / `CAP_NET_RAW` in the RouteDNS process even when used with `xsocket`.
- Supported for `udp`, `tcp`, `dot`, `doh` (including DoH/3), `doq`, `admin` and `odoh`, on both listeners and resolvers. For `dtls` it is supported on resolvers only: the DTLS library opens the listening socket internally, leaving no descriptor to inject, so a DTLS listener with `xsocket` fails to start (use `netns` instead). The same limitation applies to `fwmark`/`bind-if` on DTLS listeners.
- For SOCKS5-proxied resolvers, `xsocket` controls the connection to the proxy: RouteDNS asks the `xsocket-server` for the socket used to reach the proxy, so the proxy is contacted from inside the target namespace. The proxy's own outbound connections to the upstream resolver are made by the proxy and unaffected. Alternatively, run the SOCKS5 proxy inside the target namespace and reach it from RouteDNS's own namespace without `xsocket`.
- Linux only.

Example config files: [xsocket.toml](../cmd/routedns/example-config/xsocket.toml)

## Firewall Mark and Interface Binding

On Linux, listeners and resolvers support two socket-level options for advanced routing.

Options:

- `fwmark` - Sets the `SO_MARK` socket option. The firewall mark is attached to all packets sent from the socket, allowing Linux netfilter (`iptables`/`nftables`) and policy routing (`ip rule`) to match and route them. The value is an integer and supports TOML hex notation (e.g. `0xb`).
- `bind-if` - Sets the `SO_BINDTODEVICE` socket option. Binds the socket to a specific network interface so that traffic can only flow through that interface. This is useful with [VRFs](https://docs.kernel.org/networking/vrf.html) or as a safeguard against route leaks. On kernels >= 5.7, `SO_BINDTODEVICE` does not require root privileges.

Both options can be used independently or together on any listener or resolver. On non-Linux platforms, configuring either option returns an error. DTLS listeners do not support these options (a warning is logged). On a resolver with `socks5-address`, the options are applied to the sockets reaching the SOCKS5 proxy.

### Examples

**Resolver with fwmark and interface binding:**

Route upstream DNS traffic over a specific WAN interface using policy routing:

```toml
[resolvers.quad9-wan2]
address = "9.9.9.9:53"
protocol = "udp"
fwmark = 11
bind-if = "eth2"
```

With the corresponding routing setup:

```text
ip -4 rule add fwmark 11 table 1234
ip -4 route add default via 192.168.1.1 dev eth2 table 1234
```

**Listener bound to a VRF:**

Bind a listener to a VRF interface so it is only reachable from within that VRF:

```toml
[listeners.vrf-udp]
address = ":53"
protocol = "udp"
resolver = "upstream"
bind-if = "vrf-blue"
```

**Listener with fwmark:**

Mark packets from the listening socket for netfilter matching:

```toml
[listeners.marked-udp]
address = "[::]:53"
protocol = "udp"
resolver = "upstream"
fwmark = 12
```

Example config files: [fwmark-bind-if.toml](../cmd/routedns/example-config/fwmark-bind-if.toml)
