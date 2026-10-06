#!/usr/bin/env bash
# Generate the requests and oracle decisions for the curated RBAC
# compatibility worlds (tests/rbac_compat/worlds/*/rbac.yaml), which
# `cargo test --test rbac_compat` checks Pallograph against. Generation is
# deterministic and the output is never committed: it lands in
# target/rbac-compat/worlds/<world>/, next to a symlink to the world's
# rbac.yaml. Rerun it after changing a world or tools/rbac-oracle.
#
# Usage: hack/rbac-compat-gen.sh
#
# Requires Go (nix develop provides it).
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
target="${CARGO_TARGET_DIR:-$repo/target}"
oracle="$target/rbac-oracle"
generated="$target/rbac-compat/worlds"

go -C "$repo/tools/rbac-oracle" build -o "$oracle" .

rm -rf "$generated"
worlds=()
for source in "$repo"/tests/rbac_compat/worlds/*/; do
	world="$generated/$(basename "$source")"
	mkdir -p "$world"
	ln -s "$source/rbac.yaml" "$world/rbac.yaml"
	worlds+=("$world")
done

"$oracle" gen "${worlds[@]}"
"$oracle" eval "${worlds[@]}"
