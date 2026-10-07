#!/usr/bin/env bash
# Publish an anonymized dump as the medium fixture release asset and
# update the pin file.
#
# Only run this on output of `anonymize --check`, after reading its
# `--report` (see hack/anonymize/README.md). The release is public.
#
# Usage: hack/publish-fixtures.sh <anonymized-dir> <tag>
#   e.g. hack/publish-fixtures.sh anon fixtures-medium-v2
set -euo pipefail

REPO="ajwdev/pallograph"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:?usage: $0 <anonymized-dir> <tag>}"
TAG="${2:?usage: $0 <anonymized-dir> <tag>}"
ASSET="medium.tar.zst"
PIN="$ROOT/fixtures/testdata/medium.env"

[[ -d "$SRC" ]] || { echo "not a directory: $SRC" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Flat archive: manifests at the root, no wrapping directory. Piped through
# zstd rather than tar --zstd, which not every tar supports.
tar -cf - -C "$SRC" . | zstd -q -19 -o "$tmp/$ASSET"
# `sha256sum` format ("<hash>  <name>") so `shasum -a 256 -c` works on a
# downloaded pair.
(cd "$tmp" && shasum -a 256 "$ASSET" > "$ASSET.sha256")
sha="$(awk '{print $1}' "$tmp/$ASSET.sha256")"
echo "==> $ASSET sha256 $sha"

read -r -p "Publish $ASSET to $REPO as $TAG? [y/N] " ans
[[ "$ans" == [yY] ]] || { echo "aborted"; exit 1; }

# --latest=false: this is data, so it must not become the repo's "Latest" release.
gh release create "$TAG" "$tmp/$ASSET" "$tmp/$ASSET.sha256" --repo "$REPO" \
    --latest=false --title "$TAG" \
    --notes "Anonymized medium benchmark fixture. Verify with: shasum -a 256 -c $ASSET.sha256"

cat > "$PIN" <<PINEOF
# Pin for the medium fixture. Written by hack/publish-fixtures.sh,
# read by hack/fetch-fixtures.sh and src/engine.rs.
TAG=$TAG
ASSET=$ASSET
SHA256=$sha
PINEOF
echo "==> Updated $PIN; commit it."
