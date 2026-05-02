#!/usr/bin/env bash
set -euo pipefail

MAGNITUDE="${1:-small}"
CLUSTER_NAME="${2:-pallograph-scale}"

# Nodes | Namespaces | Pods/ns | SAs/ns
# First ceil(2/3) of SAs per namespace are referenced by pods; the rest are orphaned.
# ~10% of pods get hostNetwork, ~10% get a privileged container (interleaved).
case "$MAGNITUDE" in
  s|small)  NODES=10;   NAMESPACES=5;   PODS_PER_NS=20;  SAS_PER_NS=5  ;;
  m|medium) NODES=100;  NAMESPACES=20;  PODS_PER_NS=50;  SAS_PER_NS=10 ;;
  l|large)  NODES=500;  NAMESPACES=50;  PODS_PER_NS=200; SAS_PER_NS=20 ;;
  xl)       NODES=1000; NAMESPACES=100; PODS_PER_NS=500; SAS_PER_NS=30 ;;
  *) echo "Usage: $0 [small|medium|large|xl] [cluster-name]" >&2; exit 1 ;;
esac

TOTAL_PODS=$(( NAMESPACES * PODS_PER_NS ))
TOTAL_SAS=$(( NAMESPACES * SAS_PER_NS ))
USED_SAS_PER_NS=$(( (SAS_PER_NS * 2 + 2) / 3 ))
ORPHANED_SAS=$(( TOTAL_SAS - NAMESPACES * USED_SAS_PER_NS ))

echo "==> Magnitude: $MAGNITUDE"
printf "    Nodes:           %d\n"   "$NODES"
printf "    Namespaces:      %d\n"   "$NAMESPACES"
printf "    Total pods:      %d\n"   "$TOTAL_PODS"
printf "    Total SAs:       %d\n"   "$TOTAL_SAS"
printf "    Orphaned SAs:    %d\n"   "$ORPHANED_SAS"
printf "    ~hostNetwork:    %d\n"   "$(( TOTAL_PODS / 10 ))"
printf "    ~privileged:     %d\n"   "$(( TOTAL_PODS / 10 ))"
printf "    sa_is_cluster_admin: %d\n" "$NAMESPACES"
echo ""

for cmd in kwokctl kubectl; do
  command -v "$cmd" &>/dev/null || { echo "error: $cmd not found in PATH" >&2; exit 1; }
done

if kwokctl get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "==> Cluster '$CLUSTER_NAME' already exists; skipping create."
else
  echo "==> Creating KWOK cluster: $CLUSTER_NAME"
  kwokctl create cluster --name "$CLUSTER_NAME"
fi

KUBECTL="kubectl --context kwok-$CLUSTER_NAME"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Generating manifests..."

# Namespaces
{
  for ns in $(seq 0 $(( NAMESPACES - 1 ))); do
    printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: scale-ns-%d\n---\n' "$ns"
  done
} > "$TMPDIR/01-namespaces.yaml"

# Nodes (annotation makes KWOK manage them; capacity allows pod assignment)
{
  for i in $(seq 0 $(( NODES - 1 ))); do
    printf 'apiVersion: v1\nkind: Node\nmetadata:\n  name: kwok-node-%d\n  annotations:\n    kwok.x-k8s.io/node: fake\n  labels:\n    type: kwok\n---\n' "$i"
  done
} > "$TMPDIR/02-nodes.yaml"

# ServiceAccounts — sa-0..USED_SAS_PER_NS-1 will be referenced by pods;
# sa-USED_SAS_PER_NS..SAS_PER_NS-1 will be orphaned.
{
  for ns in $(seq 0 $(( NAMESPACES - 1 ))); do
    for sa in $(seq 0 $(( SAS_PER_NS - 1 ))); do
      printf 'apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-%d\n  namespace: scale-ns-%d\n---\n' "$sa" "$ns"
    done
  done
} > "$TMPDIR/03-serviceaccounts.yaml"

# RBAC — bind sa-0 in each namespace to cluster-admin
{
  for ns in $(seq 0 $(( NAMESPACES - 1 ))); do
    printf 'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: scale-admin-ns-%d\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n- kind: ServiceAccount\n  name: sa-0\n  namespace: scale-ns-%d\n---\n' "$ns" "$ns"
  done
} > "$TMPDIR/04-rbac.yaml"

# Pods — nodeName bypasses scheduler; toleration satisfies KWOK node taint.
# Violation seeding by global index mod 10:
#   0 → hostNetwork, 5 → privileged container, others → normal
{
  for ns in $(seq 0 $(( NAMESPACES - 1 ))); do
    for p in $(seq 0 $(( PODS_PER_NS - 1 ))); do
      g=$(( ns * PODS_PER_NS + p ))
      node=$(( g % NODES ))
      sa=$(( g % USED_SAS_PER_NS ))
      mod=$(( g % 10 ))

      if (( mod == 0 )); then
        printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-%d\n  namespace: scale-ns-%d\nspec:\n  nodeName: kwok-node-%d\n  serviceAccountName: sa-%d\n  hostNetwork: true\n  tolerations:\n  - {key: kwok.x-k8s.io/node, operator: Exists, effect: NoSchedule}\n  containers:\n  - name: pause\n    image: registry.k8s.io/pause:3.9\n---\n' \
          "$p" "$ns" "$node" "$sa"
      elif (( mod == 5 )); then
        printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-%d\n  namespace: scale-ns-%d\nspec:\n  nodeName: kwok-node-%d\n  serviceAccountName: sa-%d\n  tolerations:\n  - {key: kwok.x-k8s.io/node, operator: Exists, effect: NoSchedule}\n  containers:\n  - name: pause\n    image: registry.k8s.io/pause:3.9\n    securityContext:\n      privileged: true\n---\n' \
          "$p" "$ns" "$node" "$sa"
      else
        printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-%d\n  namespace: scale-ns-%d\nspec:\n  nodeName: kwok-node-%d\n  serviceAccountName: sa-%d\n  tolerations:\n  - {key: kwok.x-k8s.io/node, operator: Exists, effect: NoSchedule}\n  containers:\n  - name: pause\n    image: registry.k8s.io/pause:3.9\n---\n' \
          "$p" "$ns" "$node" "$sa"
      fi
    done
  done
} > "$TMPDIR/05-pods.yaml"

echo "==> Applying (this may take a few minutes for large/xl)..."
$KUBECTL apply -f "$TMPDIR/01-namespaces.yaml"
$KUBECTL apply -f "$TMPDIR/02-nodes.yaml"
$KUBECTL apply -f "$TMPDIR/03-serviceaccounts.yaml"
$KUBECTL apply -f "$TMPDIR/04-rbac.yaml"
$KUBECTL apply --server-side -f "$TMPDIR/05-pods.yaml"

echo ""
echo "Done. Run against this cluster:"
echo "  cargo run -- --live"
echo "  cargo run -- --live --repl"
echo ""
echo "Tear down: hack/kwok-down.sh $CLUSTER_NAME"
