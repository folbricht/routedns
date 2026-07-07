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

FROM alpine:latest
COPY --from=builder /routedns /routedns
COPY cmd/routedns/example-config/simple-dot-proxy.toml /config.toml
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/routedns"]
CMD ["config.toml"]
