#!/bin/sh
set -e

arch=$(uname -m)

if [ "$arch" = "x86_64" ]; then
    goarch="amd64"
elif [ "$arch" = "armv7l" ]; then
    goarch="arm"
elif [ "$arch" = "aarch64" ]; then
    goarch="arm64"
elif [ "$arch" = "arm64" ]; then
    goarch="arm64"
else
    printf "Platform '%s' is not supported\n" "$arch" >&2
    exit 1
fi

GOOS="linux" GOARCH="$goarch" CGO_ENABLED=0 go build 
