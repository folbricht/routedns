# Image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with the repository as the context and network
# access, then runs its analysis inside the image offline. Everything the
# build, the tests and any reproducer need has to be fetched here.
FROM golang:trixie

ENV DEBIAN_FRONTEND=noninteractive \
	GOTOOLCHAIN=local

# dig and kdig to send crafted queries to a running instance over plain DNS,
# DoT, DoH and DoQ.
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates git iproute2 procps dnsutils knot-dnsutils \
	&& rm -rf /var/lib/apt/lists/*

# The scanner's contract: the checkout lives in the image at /src.
COPY . /src
WORKDIR /src

# A normal build with debug info, unlike the release image.
RUN go mod download \
	&& go build -o /usr/local/bin/routedns ./cmd/routedns

# Runs the suite once to warm the build cache. A few client tests query public
# resolvers and fail offline, so failures must not abort the image build.
RUN go test ./... || echo "WARNING: go test reported failures"

# Reproducers and patches have to build without the network.
ENV GOPROXY=off \
	GOSUMDB=off

CMD ["bash"]
