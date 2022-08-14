#!/bin/sh
set -e

arch=$(uname -m)

case "$arch" in
"x86_64")
    goarch="amd64"
    ;;
"armv7l")
    goarch="arm"
    ;;
"aarch64")
    goarch="arm64"
    ;;
"arm64")
    goarch="arm64"
    ;;
*)
    printf "Platform '%s' is not supported\n" "$arch" >&2
    exit 1
esac

GOOS="linux" GOARCH="$goarch" CGO_ENABLED=0 go build 
