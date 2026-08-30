#!/usr/bin/env bash
#
# Consistency checks for the documentation. Run from the repository root:
#
#   .github/scripts/check-docs.sh
#
# Every check here has caught a real defect at least once. See #623 for the
# anchor and link problems, #624 and #625 for the example config coverage.
set -uo pipefail

cd "$(dirname "$0")/../.."

GUIDE=doc/configuration.md
EXAMPLES=cmd/routedns/example-config
# The guide is doc/configuration.md (an index) plus one page per topic.
DOCS=(README.md "$EXAMPLES/README.md" doc/*.md)

fail=0
report() {
	echo "FAIL: $1"
	fail=1
}

# GitHub derives a heading id by lowercasing, dropping anything that is not a
# letter, digit, space or dash, and turning spaces into dashes.
anchors_of() {
	grep '^#\{1,4\} ' "$1" |
		sed 's/^#* //' |
		tr 'A-Z' 'a-z' |
		sed 's/[^a-z0-9 -]//g' |
		tr ' ' '-'
}

echo "==> relative links resolve"
for f in "${DOCS[@]}"; do
	dir=$(dirname "$f")
	grep -o '](\([a-zA-Z0-9._/-]\+\))' "$f" |
		sed 's/](//; s/)$//' |
		sort -u |
		while read -r link; do
			[ -e "$dir/$link" ] || echo "  $f -> $link"
		done
done | grep . && report "links above point at files that do not exist"

echo "==> in-document anchors resolve"
for f in "${DOCS[@]}"; do
	anchors_of "$f" | sort -u >/tmp/rdns-anchors.$$
	grep -o '](#[^)]*)' "$f" |
		sed 's/](#//; s/)//' |
		sort -u |
		while read -r a; do
			grep -qx "$a" /tmp/rdns-anchors.$$ || echo "  $f -> #$a"
		done
	rm -f /tmp/rdns-anchors.$$
done | grep . && report "anchors above match no heading"

# Two sections rendering to the same id makes GitHub append -1 to the second,
# so links to either one land in the wrong place. Repeated #### headings
# (Configuration, Examples) are expected and nothing links to them.
echo "==> no duplicate section anchors"
for f in "${DOCS[@]}"; do
	anchors_of "$f" |
		grep -vxE 'configuration|examples' |
		sort | uniq -d |
		sed "s|^|  $f -> |"
done | grep . && report "headings above render to the same anchor"

echo "==> nothing links to the exempted structural anchors"
grep -rn '](#configuration)\|](#examples)' README.md doc/ "$EXAMPLES/README.md" |
	sed 's/^/  /' | grep . &&
	report "the duplicate-anchor check exempts these two anchors, so nothing may link to them"

echo "==> every config option is documented"
grep -oE 'toml:"[a-z0-9-]+"' cmd/routedns/config.go |
	sed 's/toml:"//; s/"//' |
	sort -u |
	while read -r opt; do
		grep -qr "\b$opt\b" doc/ || echo "  $opt"
	done | grep . && report "options above appear in config.go but not in doc/"

echo "==> every example is indexed and described"
for f in "$EXAMPLES"/*.toml; do
	base=$(basename "$f")
	head -1 "$f" | grep -q '^#' || echo "  $base has no header comment"
	grep -q "($base)" "$EXAMPLES/README.md" || echo "  $base is missing from the index"
done | grep . && report "examples above are undocumented"

if [ "$fail" -eq 0 ]; then
	echo "docs are consistent"
fi
exit "$fail"
