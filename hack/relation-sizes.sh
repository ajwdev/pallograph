#!/usr/bin/env bash
# Print how many rows the RBAC and escalation rules derive, per relation and
# in total, for one rules directory and one set of Kubernetes manifests.
# Use it to compare rule revisions: every relation a rule head in
# rbac*.mg or escalation.mg defines is counted, so the total covers
# intermediate relations too, whatever a revision calls them.
#
# Usage: hack/relation-sizes.sh [-b BINARY] RULES_DIR DATA_PATH...
#
# DATA_PATH is a file or directory of k8s JSON/YAML manifests, as for a
# "file" datasource. BINARY defaults to target/release/pallograph, so run
# `cargo build --release` first. Older revisions' rules can be extracted
# with: git archive <rev> rules | tar -x -C <dir>
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
binary="$repo/target/release/pallograph"
while getopts "b:" option; do
	case "$option" in
	b) binary="$OPTARG" ;;
	*) echo "usage: $0 [-b BINARY] RULES_DIR DATA_PATH..." >&2; exit 2 ;;
	esac
done
shift $((OPTIND - 1))
if [[ $# -lt 2 ]]; then
	echo "usage: $0 [-b BINARY] RULES_DIR DATA_PATH..." >&2
	exit 2
fi
rules="$(cd "$1" && pwd)"
shift

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

paths=""
for path in "$@"; do
	paths+="\"$(realpath "$path")\", "
done
cat >"$scratch/config.toml" <<EOF
default_profile = "dev"
[datasources.local]
source = "file"
paths = [${paths%, }]
content = "k8s-manifests"
[profiles.dev]
sources = ["local"]
EOF

# Relations defined by a rule head at the start of a line. Relations that
# only hold rows for access_request input are skipped: they are empty here.
mapfile -t relations < <(
	cat "$rules"/rbac*.mg "$rules"/escalation.mg |
		grep -oE '^[a-z_][a-z0-9_]*\(' | tr -d '(' |
		grep -vE '^(rbac_allowed|request_|access_request_)' | sort -u
)

# The REPL reports each query's row count on stderr, one line per query, in
# order: "Found N result(s).", "No results." or "Unknown relation".
printf '?- %s\n' "${relations[@]}" |
	"$binary" --rules "$rules" -C "$scratch/config.toml" --format ndjson 2>"$scratch/stderr" >/dev/null
mapfile -t counts < <(
	grep -E '^(Found [0-9]+ result|No results|Unknown relation)' "$scratch/stderr" |
		sed -E 's/^Found ([0-9]+).*/\1/; s/^No results.*/0/; s/^Unknown relation.*/-/'
)
if [[ ${#counts[@]} -ne ${#relations[@]} ]]; then
	echo "expected ${#relations[@]} counts, got ${#counts[@]}; REPL stderr:" >&2
	grep -v '^\[mangle\]' "$scratch/stderr" >&2
	exit 1
fi

total=0
for i in "${!relations[@]}"; do
	printf '%-40s %s\n' "${relations[$i]}" "${counts[$i]}"
	if [[ ${counts[$i]} != - ]]; then
		total=$((total + counts[i]))
	fi
done
printf '%-40s %s\n' TOTAL "$total"
