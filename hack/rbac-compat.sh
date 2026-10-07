#!/usr/bin/env bash
# Fuzz tier of the RBAC compatibility harness: generate random RBAC worlds,
# decide their requests with the kube-apiserver authorizer (tools/rbac-oracle),
# then check Pallograph's rbac_allowed against those decisions.
#
# Usage: hack/rbac-compat.sh [-s SEED] [-n COUNT]
#
# Worlds land in target/rbac-compat-fuzz/seed-<SEED>, so a run is
# reproducible from its seed. Requires Go.
set -euo pipefail

seed="$(date +%s)"
count=50
while getopts "s:n:" option; do
	case "$option" in
	s) seed="$OPTARG" ;;
	n) count="$OPTARG" ;;
	*) echo "usage: $0 [-s SEED] [-n COUNT]" >&2; exit 2 ;;
	esac
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
worlds="$repo/target/rbac-compat-fuzz/seed-$seed"
oracle="$repo/target/rbac-oracle"

echo "seed $seed, $count worlds in $worlds" >&2
rm -rf "$worlds"
go -C "$repo/tools/rbac-oracle" build -o "$oracle" .
"$oracle" gen-worlds -seed "$seed" -count "$count" "$worlds"
"$oracle" gen "$worlds"/*/ 2>/dev/null
"$oracle" eval "$worlds"/*/ 2>/dev/null

RBAC_COMPAT_WORLDS="$worlds" cargo test --release --test rbac_compat -- \
	--ignored --exact fuzz_worlds --nocapture 2>&1 | grep -v '^\[mangle\]'
