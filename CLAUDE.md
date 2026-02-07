# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RouteDNS is a composable DNS stub resolver, proxy and router written in Go. It builds processing pipelines from four component types (listeners, resolvers, groups/modifiers, routers) configured via TOML files.

## Build & Test Commands

```bash
# Build
go build -o cmd/desync/ ./cmd/routedns

# Run all tests
go test ./...

# Run a single test
go test -run TestCacheLookupAndExpiry ./...

# Run tests in a specific package
go test ./dnssec/

# Run with race detector
go test -race ./...

# Run the binary
routedns config.toml
```

There is no Makefile or linter configuration. CI uses GitHub Actions with CodeQL analysis only.

## Architecture

### Core Abstraction

Every component in the pipeline implements the `Resolver` interface (`resolver.go`):

```go
type Resolver interface {
    Resolve(*dns.Msg, ClientInfo) (*dns.Msg, error)
    fmt.Stringer
}
```

This single interface is implemented by clients, groups, modifiers, and routers alike, enabling arbitrary composition.

### Pipeline Flow

```
Listeners (receive DNS queries over UDP/TCP/DoT/DoH/DoQ/DTLS/ODoH)
    ↓
Routers (route based on query name, type, source IP, time, etc.)
    ↓
Groups/Modifiers (cache, blocklist, load-balance, transform)
    ↓
Resolvers/Clients (forward to upstream DNS servers)
```

### Component Types

- **Listeners** (`Listener` interface in `listener.go`): Entry points that accept DNS queries. Each protocol has its own file (e.g., `dohlistener.go`, `dotlistener.go`, `doqlistener.go`).
- **Clients/Resolvers**: Forward queries upstream. Each protocol is in its own file (`dnsclient.go` for UDP/TCP, `dotclient.go`, `dohclient.go`, `doqclient.go`, `dtlsclient.go`, `odohclient.go`).
- **Groups/Modifiers** (~30 types): Wrap one or more resolvers to add behavior — caching (`cache.go`), blocklists (`blocklist-v2.go`), load-balancing (`round-robin.go`, `failrotate.go`, `fastest.go`), rate limiting (`rate-limiter.go`), query/response modification, etc.
- **Routers** (`router.go`): Conditional routing based on query properties (name regex, type, source IP, time of day, etc.). Routes evaluated in order; first match wins.

### Configuration System

TOML-based configuration defined in `cmd/routedns/config.go`. Four top-level sections: `[listeners]`, `[resolvers]`, `[groups]`, `[routers]`. Component instantiation in `cmd/routedns/resolver.go` uses a DAG (`github.com/heimdalr/dag`) to resolve dependencies bottom-up, preventing circular references.

Multiple config files can be provided as arguments and are merged.

### Key Patterns

- **Go package name**: `rdns` (import as `github.com/folbricht/routedns`)
- **Composition via Resolver interface**: Groups/modifiers wrap inner resolvers, creating decorator chains
- **Options structs**: Constructors take `*XxxOptions` structs (e.g., `CacheOptions`, `DNSClientOptions`)
- **Metrics**: Components export metrics via `expvar` using the pattern `routedns.<base>.<id>.<metric>`
- **Graceful shutdown**: `onClose` functions registered globally, triggered on SIGTERM/SIGINT
- **Blocklist databases**: `BlocklistDB` interface with implementations for domains, regex, hosts, CIDR, GeoIP, ASN, MAC formats

### Testing

Tests use a `TestResolver` mock (returns the query as-is or a configured response). Test files live alongside source files. Some tests require network access (DoH/DoT/DoQ client tests connect to real servers).
