#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${1:-pallograph-test}"

echo "==> Deleting KinD cluster: $CLUSTER_NAME"
kind delete cluster --name "$CLUSTER_NAME"
