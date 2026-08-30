#!/usr/bin/env bash
#
# Loads every example configuration with "routedns --check". Run from the
# repository root:
#
#   .github/scripts/check-examples.sh
#
# --check builds everything a config defines without binding a port, which
# means it reads certificates, loads blocklists from their sources including
# over HTTP, and connects to Redis. Reaching the network is the point: #619
# found every cbuijs blocklist URL returning 404 after that repo moved to
# "main". It also means a third-party outage shows up here as a failure.
set -uo pipefail

cd "$(dirname "$0")/../.."

BIN=$(mktemp -d)/routedns
go build -o "$BIN" ./cmd/routedns || exit 1

# Configurations that cannot load without something the checkout does not
# carry. Two groups, because they behave differently by environment.
#
# The placeholder group is unconditional: these reference
# /path/to/{ca,client,server}.{crt,key}, which a reader is meant to replace.
PLACEHOLDER_CERTS=(
	mutual-tls-doh-client.toml
	mutual-tls-doh-server.toml
	mutual-tls-dot-client.toml
	mutual-tls-dot-server.toml
	use-case-5-client.toml
	use-case-5-server.toml
)

# The geo group depends on MaxMind databases that are not redistributable and
# so are not in the repo. They are absent on CI runners and may be installed on
# a developer machine, so whether these are expected to fail is decided by
# looking for the file rather than hard-coded.
#
# These are the paths the blocklists default to, from geoip-db.go and
# asn-db.go. They are not configurable here on purpose: the check has to ask
# the same question routedns will, or the two disagree and every run reports a
# file that is fine.
GEO_CITY_DB=/usr/share/GeoIP/GeoLite2-City.mmdb
GEO_ASN_DB=/usr/share/GeoIP/GeoLite2-ASN.mmdb

EXPECTED_FAIL=("${PLACEHOLDER_CERTS[@]}")
[ -f "$GEO_CITY_DB" ] || EXPECTED_FAIL+=(client-blocklist-geo.toml response-blocklist-geo.toml)
[ -f "$GEO_ASN_DB" ] || EXPECTED_FAIL+=(response-blocklist-asn.toml)

is_expected_fail() {
	local name=$1
	for e in "${EXPECTED_FAIL[@]}"; do
		[ "$e" = "$name" ] && return 0
	done
	return 1
}

cd cmd/routedns

pass=0 skip=0
unexpected_fail=() unexpected_pass=()

for f in example-config/*.toml; do
	name=$(basename "$f")
	if timeout 60 "$BIN" --check "$f" >/dev/null 2>&1; then
		if is_expected_fail "$name"; then
			unexpected_pass+=("$name")
		else
			pass=$((pass + 1))
		fi
	else
		if is_expected_fail "$name"; then
			skip=$((skip + 1))
		else
			unexpected_fail+=("$name")
		fi
	fi
done

echo "$pass validated, $skip expected to fail"

status=0

if [ ${#unexpected_fail[@]} -gt 0 ]; then
	echo
	echo "FAIL: these configurations no longer load:"
	for name in "${unexpected_fail[@]}"; do
		echo "  $name"
		"$BIN" --check "example-config/$name" 2>&1 | tail -3 | sed 's/^/      /'
	done
	status=1
fi

if [ ${#unexpected_pass[@]} -gt 0 ]; then
	echo
	echo "FAIL: these are listed in EXPECTED_FAIL but load fine now."
	echo "Remove them from the list in $0:"
	printf '  %s\n' "${unexpected_pass[@]}"
	status=1
fi

exit "$status"
