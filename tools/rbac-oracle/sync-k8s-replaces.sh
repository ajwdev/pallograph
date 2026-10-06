#!/usr/bin/env bash
# Pin k8s.io/kubernetes and rewrite the go.mod replace block for its
# staging modules. k8s.io/kubernetes declares every k8s.io/* staging module
# as v0.0.0 with a ./staging replace, which does not resolve for consumers,
# so each one has to be pointed at its published v0.<minor>.<patch> tag.
#
# Usage: ./sync-k8s-replaces.sh [v1.37.1]
set -euo pipefail

cd "$(dirname "$0")"

version="${1:-v1.37.1}"
staging_version="v0.${version#v1.}"

# Drop the previous version's replaces first, so staging modules removed
# upstream do not linger.
for module in $(go mod edit -json | jq -r '.Replace[]?.Old.Path | select(startswith("k8s.io/"))'); do
	go mod edit -dropreplace "$module"
done

replaces=$(curl -fsSL "https://proxy.golang.org/k8s.io/kubernetes/@v/${version}.mod" |
	awk '/=> \.\/staging/ { print $1 }')

for module in $replaces; do
	go mod edit -replace "${module}=${module}@${staging_version}"
done
go mod edit -require "k8s.io/kubernetes@${version}"
go mod tidy
