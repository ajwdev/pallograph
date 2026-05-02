#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${1:-pallograph-scale}"

echo "==> Deleting KWOK cluster: $CLUSTER_NAME"
kwokctl delete cluster --name "$CLUSTER_NAME"
