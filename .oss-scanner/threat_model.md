# RouteDNS threat model

RouteDNS is a DNS stub resolver, proxy and router. It accepts queries over
plain DNS (UDP/TCP), DoT, DoH (HTTP/2 and HTTP/3), DoQ, DTLS and ODoH, passes
them through a pipeline of routers, groups and modifiers (cache, blocklists,
rate limiter, DNSSEC validator, Lua scripts, and so on) configured in TOML,
and forwards them to upstream resolvers over the same set of protocols. It
typically runs as the resolver for a home or office network, sometimes on
constrained hardware such as an OpenWrt router, and sometimes exposed to the
internet as a public DoH/DoT endpoint.

## Where untrusted input enters

- **Clients of every listener.** Any DNS message, TLS/QUIC handshake, HTTP
  request (method, path, query string, headers, body) and connection
  behaviour from a client is untrusted. Assume the attacker can reach the
  listener. `allowed-net` restricts who may query, and a bypass of it is in
  scope.
- **Upstream responses.** Responses from upstream resolvers are untrusted.
  Plain DNS upstreams can be spoofed off-path; any upstream may return
  malformed, oversized or mismatched answers.
- **Remote blocklists and trust anchors.** Lists fetched over HTTP(S)
  (`blocklistloader-http.go`) and trust anchors from `dnssec-trust-anchor-url`
  come from a third party the operator chose. Treat their content as
  untrusted, though the operator trusts the source not to be malicious in
  intent.
- **Cache files and Redis.** A persisted cache file or Redis instance is
  operator controlled, so corruption there is a robustness issue, not an
  attack.

## What is trusted

- The TOML configuration, any files it references, and Lua scripts. Lua is
  operator code; escaping it or making it misbehave with a crafted script is
  out of scope. A query that makes a correct script misbehave is in scope.
- The admin listener (metrics) is meant for operators. Reports should still
  cover it if it can be reached without the configured TLS/mTLS.
- The xsocket fd-server Unix socket and network namespace setup are local
  privileged interfaces. A local unprivileged user getting sockets they
  should not is in scope; anything requiring root is not.
- A reverse proxy in a DoH listener's `trusted-proxy` subnet is trusted to set
  `X-Forwarded-For`. Spoofing that header from outside the subnet is in scope.

## What matters most

1. Message parsing and handling on the listeners, including the DoH, DoQ and
   ODoH framing, and the 0-RTT handling in DoQ/DoH3.
2. The cache (`cache*.go`, `lru-cache.go`, `packbuf.go`): poisoning, serving
   one client's answer to another for a different question, or corrupting
   entries.
3. Response handling from upstreams: ID/question matching, truncation retry,
   and anything that could feed a forged answer to a client.
4. The DNSSEC validator (`dnssec*.go`, `dnssec/`): accepting a bogus answer
   as secure.
5. Access control: `allowed-net`, client blocklists, rate limiter, and the
   client identity those rely on (source address, `X-Forwarded-For`, ECS).

## How to exercise it

- `/usr/local/bin/routedns <config.toml>` runs the daemon. The configs in
  `cmd/routedns/example-config/` cover every component; most forward to
  public resolvers, which are unreachable in the scanner, so point their
  resolvers at a local listener or a `static-responder` instead.
- `dig` and `kdig` (which speaks DoT, DoH and DoQ) are installed to send
  queries.
- `go test ./...` runs the suite. These tests contact public resolvers and
  fail without network access: `TestDNSClientSimpleTCP`,
  `TestDNSClientSimpleUDP`, `TestDoHClientSimplePOST`,
  `TestDoHClientSimpleGET`, `TestDOQSimple`, `TestDoTClientSimple`,
  `TestDoTClientCA`, `TestNetDialer`, `TestNetResolver`,
  `TestODOHClientSimple`. `TestWaitNetNSReadyOnMount` needs root with mount
  privileges and fails in an unprivileged container. The listener tests use
  loopback and work offline.
- Build tags `nolua` and `noredis` drop those components; the default build
  includes both.

## Severity

- **Critical:** forging or poisoning answers served to other clients (cache
  poisoning, accepting spoofed upstream responses, DNSSEC validation bypass
  that returns a forged answer as secure), or remote code execution.
- **High:** a remote, unauthenticated client crashing the process (panic,
  fatal error, deadlock) with a small number of queries, since that takes
  name resolution down for the whole network. Bypassing `allowed-net`.
- **Medium:** bypassing a client blocklist, rate limiter or domain blocklist
  through crafted input. Memory or goroutine growth that a single client can
  drive to exhaustion faster than by sending ordinary queries at the same
  rate. Leaking one client's data to another.
- **Low:** issues that need an unusual, non-default configuration combined
  with attacker input, and information leaks with no practical use.

Volumetric DoS (flooding the listener) and reflection through an open
resolver the operator chose to expose are not vulnerabilities in RouteDNS.

## Leave alone

- Private keys under `testdata/` and `cmd/routedns/example-config/` are test
  fixtures, not leaked secrets.
- Issues in dependencies (`miekg/dns`, `quic-go`, `pion/dtls`, `gopher-lua`,
  ...) only matter if they are reachable through RouteDNS; report them with
  that path.
- Weak settings an operator explicitly configured (no TLS, no `allowed-net`,
  `dnssec-log-only`, a permissive Lua script).

## Reports and patches

Include a config and a reproducer (`dig`/`kdig` command or Go test). Patches
should be minimal, keep the existing code style, and come with a test in the
matching `_test.go` file.
