#!/usr/bin/env bash
# Fetch a fixture tier from its GitHub release, verify the pinned sha256,
# and extract it to fixtures/testdata/<name>/.
#
# Usage: hack/fetch-fixtures.sh medium
set -euo pipefail

REPO="ajwdev/pallograph"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${1:?usage: $0 medium}"
PIN="$ROOT/fixtures/testdata/$NAME.env"
DEST="$ROOT/fixtures/testdata/$NAME"

[[ -f "$PIN" ]] || { echo "no pin file: $PIN" >&2; exit 1; }
# shellcheck source=/dev/null
source "$PIN"

if [[ "$(cat "$DEST/.sha256" 2>/dev/null || true)" == "$SHA256" ]]; then
    echo "$NAME fixture up to date ($SHA256)"
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# FIXTURES_BASE_URL exists so the verify path can be tested without the network.
url="${FIXTURES_BASE_URL:-https://github.com/$REPO/releases/download/$TAG}/$ASSET"
echo "==> Downloading $url"
curl -fL --progress-bar -o "$tmp/$ASSET" "$url"

got="$(shasum -a 256 "$tmp/$ASSET" | awk '{print $1}')"
if [[ "$got" != "$SHA256" ]]; then
    echo "sha256 mismatch for $ASSET" >&2
    echo "  expected: $SHA256" >&2
    echo "  actual:   $got" >&2
    exit 1
fi

mkdir "$tmp/extract"
zstd -dc "$tmp/$ASSET" | tar -xf - -C "$tmp/extract"
echo "$SHA256" > "$tmp/extract/.sha256"

rm -rf "$DEST"
mv "$tmp/extract" "$DEST"
echo "==> $NAME fixture ready at $DEST"
