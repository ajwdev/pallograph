#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${1:-pallograph-test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$SCRIPT_DIR/../testdata/kind"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    echo "Cluster '$CLUSTER_NAME' already exists; skipping create."
else
    echo "==> Creating KinD cluster: $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME"
fi

echo "==> Applying test manifests"
kubectl --context "kind-$CLUSTER_NAME" apply -f "$MANIFESTS_DIR"

echo ""
echo "Done. Expected policy hits against this cluster:"
echo "  orphaned_sa:       pallograph-test/orphaned-sa"
echo "  privileged_pod:    pallograph-test/privileged-pod"
echo "  host_network_pod:  pallograph-test/host-network-pod"
echo "  sa_is_cluster_admin: pallograph-test/admin-sa"
echo "  role_has_wildcard_verb: pallograph-test/wildcard-role"
echo ""
echo "Run:  cargo run -- --live"
echo "REPL: cargo run -- --live --repl"
echo ""
echo "Tear down: hack/kind-down.sh $CLUSTER_NAME"
