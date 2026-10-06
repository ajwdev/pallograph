#!/usr/bin/env bash
# Check the RBAC oracle (tools/rbac-oracle) against a live kube-apiserver:
# apply each world to a kind cluster and compare the oracle's decisions and
# ClusterRole aggregation with the API server's. This validates the oracle,
# not Pallograph.
#
# Usage: hack/rbac-kind-verify.sh [world...]
#
# Defaults to the curated worlds under tests/rbac_compat/worlds. Creates the
# kind cluster on first use and leaves it running; remove it with
#   kind delete cluster --name pallograph-rbac-compat
# Extra flags for rbac-oracle kind-verify (e.g. -sample 0) go in
# RBAC_KIND_VERIFY_FLAGS.
set -euo pipefail

cluster=pallograph-rbac-compat
# Matches the k8s.io/kubernetes version the oracle links (v1.37.1); kind
# publishes no v1.37.1 node image, and RBAC does not change in patches.
# Kubernetes 1.37 needs kind v0.32.0 or later (kubeadm v1beta4 config), so
# kind is pinned here rather than taken from PATH.
image=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
kind() { go run sigs.k8s.io/kind@v0.33.0 "$@"; }

repo="$(cd "$(dirname "$0")/.." && pwd)"
oracle="$repo/target/rbac-oracle"

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
	kind create cluster --name "$cluster" --image "$image" --wait 120s
fi

go -C "$repo/tools/rbac-oracle" build -o "$oracle" .
if [ "$#" -eq 0 ]; then
	set -- "$repo"/tests/rbac_compat/worlds/*/
fi
# shellcheck disable=SC2086
"$oracle" kind-verify -context "kind-$cluster" ${RBAC_KIND_VERIFY_FLAGS:-} "$@"
