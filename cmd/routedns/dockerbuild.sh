#!/bin/sh
set -e

hostarch(){
    arch=$(uname -m)

    case "$arch" in
    "x86_64")
        printf "amd64"
        ;;
    "armv7l")
        printf "arm"
        ;;
    "aarch64")
        printf "arm64"
        ;;
    "arm64")
        printf "arm64"
        ;;
    *)
        printf "Platform '%s' is not supported\n" "$arch" >&2
        exit 1
    esac
}   

if [ "$1" = "" ]; then
    goarch=$(hostarch)
else
    goarch="$1"
fi

printf "Build with GOARCH='%s'\n" "$goarch"
GOOS="linux" GOARCH="$goarch" CGO_ENABLED=0 go build 
