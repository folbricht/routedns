FROM golang:alpine as builder
ARG GOOS
ARG GOARCH

WORKDIR /build
COPY . .
WORKDIR cmd/routedns
RUN GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build 

FROM alpine:latest
COPY --from=builder /build/cmd/routedns/routedns .
COPY cmd/routedns/example-config/simple-dot-proxy.toml config.toml
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/routedns"]
CMD ["config.toml"]
