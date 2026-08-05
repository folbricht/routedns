# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

Build the binary into `cmd/routedns/`, never the repo root:

```bash
go build -o cmd/routedns/ ./cmd/routedns
```

## Conventions & gotchas

- **Go package name is `rdns`**, not `routedns` — import as `github.com/folbricht/routedns`.
- **Metrics naming**: components export metrics via `expvar` as `routedns.<base>.<id>.<metric>`.
- **Config type names don't always match file names** — e.g. `blocklist.go` is config type `blocklist-v2`.
- **Some tests require network access** — the DoH/DoT/DoQ client tests connect to real servers.
- Component instantiation in `cmd/routedns/main.go` uses a DAG so dependencies resolve bottom-up, which is what prevents circular references.
