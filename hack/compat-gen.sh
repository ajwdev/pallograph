#!/usr/bin/env bash
# Generate the oracle data the compatibility tests check Pallograph against,
# with tools/k8s-oracle (upstream Kubernetes code). Generation is
# deterministic and the output is never committed. Rerun it after changing
# a world or tools/k8s-oracle.
#
# The RBAC data is the requests and kube-apiserver decisions for the curated
# worlds (tests/rbac_compat/worlds/*/rbac.yaml), which `cargo test --test
# rbac_compat` checks. It lands in target/rbac-compat/worlds/<world>/, next
# to a symlink to the world's rbac.yaml.
#
# Usage: hack/compat-gen.sh
#
# Requires Go (nix develop provides it).
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
target="${CARGO_TARGET_DIR:-$repo/target}"
oracle="$target/k8s-oracle"

go -C "$repo/tools/k8s-oracle" build -o "$oracle" .

generated="$target/rbac-compat/worlds"
rm -rf "$generated"
worlds=()
for source in "$repo"/tests/rbac_compat/worlds/*/; do
	world="$generated/$(basename "$source")"
	mkdir -p "$world"
	ln -s "$source/rbac.yaml" "$world/rbac.yaml"
	worlds+=("$world")
done

"$oracle" rbac gen "${worlds[@]}"
"$oracle" rbac eval "${worlds[@]}"
