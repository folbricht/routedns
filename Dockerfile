# Cross-compiles on the build host (BUILDPLATFORM) so multi-arch images
# build without emulation. TARGETOS/TARGETARCH/TARGETVARIANT are set
# automatically by buildx for each requested platform.
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 \
	go build -trimpath -ldflags="-s -w" -o /routedns ./cmd/routedns

# Distroless static base: no shell, package manager, or userland — only the
# static binary plus CA certs, tzdata, and /etc/passwd. The :latest tag runs as
# root (uid 0), so the daemon binds privileged port 53 with no extra runtime
# flags. Works because the binary is CGO_ENABLED=0 (fully static).
FROM gcr.io/distroless/static-debian13:latest
COPY --from=builder /routedns /routedns
COPY cmd/routedns/example-config/simple-dot-proxy.toml /config.toml
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/routedns"]
CMD ["/config.toml"]
