#!/usr/bin/env bash
# Check the RBAC oracle (tools/rbac-oracle) against a live kube-apiserver:
# apply each world to a kind cluster and compare the oracle's decisions and
# ClusterRole aggregation with the API server's. This validates the oracle,
# not Pallograph.
#
# Usage: hack/rbac-kind-verify.sh [world...]
#
# Run it from the dev shell (nix develop), which provides go and kind.
# Defaults to the curated worlds under tests/rbac_compat/worlds, generated
# first with hack/rbac-compat-gen.sh. Creates the kind cluster on first use
# and leaves it running; remove it with
#   kind delete cluster --name pallograph-rbac-compat
# Extra flags for rbac-oracle kind-verify (e.g. -sample 0) go in
# RBAC_KIND_VERIFY_FLAGS.
set -euo pipefail

cluster=pallograph-rbac-compat
# Matches the k8s.io/kubernetes version the oracle links (v1.37.1); kind
# publishes no v1.37.1 node image, and RBAC does not change in patches.
image=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5

# Kubernetes 1.37 needs kind v0.32.0 or later (kubeadm v1beta4 config);
# older kind fails deep inside kubeadm init.
kind_version="$(kind version | awk '{print $2}')"
if [ "$(printf '%s\n' v0.32.0 "$kind_version" | sort -V | head -1)" != v0.32.0 ]; then
	echo "$0: kind $kind_version is too old for Kubernetes 1.37; need v0.32.0+ (try nix develop)" >&2
	exit 1
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"
target="${CARGO_TARGET_DIR:-$repo/target}"
oracle="$target/rbac-oracle"

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
	kind create cluster --name "$cluster" --image "$image" --wait 120s
fi

if [ "$#" -eq 0 ]; then
	"$repo/hack/rbac-compat-gen.sh"
	set -- "$target"/rbac-compat/worlds/*/
else
	go -C "$repo/tools/rbac-oracle" build -o "$oracle" .
fi
# shellcheck disable=SC2086
"$oracle" kind-verify -context "kind-$cluster" ${RBAC_KIND_VERIFY_FLAGS:-} "$@"
