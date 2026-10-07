#!/usr/bin/env bash
# Build and publish the medium fixture release asset.
#
#   hack/publish-fixtures.sh pack <anonymized-dir> <out-dir>
#   hack/publish-fixtures.sh upload <out-dir> [ref]
#
# `pack` builds medium.tar.zst and medium.tar.zst.sha256 in <out-dir> and
# writes the archive's sha256 into fixtures/testdata/medium.env. Commit that
# file. Pack once and keep <out-dir>: the pin is the hash of those exact bytes
# (the anonymizer's default seed is random and tar records mtimes, so a rebuild
# will not match).
#
# `upload` checks that the archive in <out-dir> still matches the pin, then
# creates the release named by the pin's TAG. Pass the merge commit as [ref]
# to tag that commit (a full SHA or branch on the remote); it defaults to the
# repo's default branch.
#
# Only pack the output of `anonymize --check`, after reading its `--report`
# (see hack/anonymize/README.md). The release is public.
set -euo pipefail

REPO="ajwdev/pallograph"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN="$ROOT/fixtures/testdata/medium.env"
GH="${GH:-gh}" # overridable so the argument handling can be tested

usage() {
    sed -n '2,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//' >&2
    exit 2
}

sha_of() { shasum -a 256 "$1" | awk '{print $1}'; }

# shellcheck source=/dev/null
load_pin() { [[ -f "$PIN" ]] || { echo "no pin file: $PIN" >&2; exit 1; }; source "$PIN"; }

pack() {
    [[ $# -eq 2 ]] || usage
    local src="$1" out="$2"
    [[ -d "$src" ]] || { echo "not a directory: $src" >&2; exit 1; }
    load_pin
    mkdir -p "$out"
    [[ -z "$(ls -A "$out")" ]] || { echo "out dir not empty: $out" >&2; exit 1; }

    # Flat archive: manifests at the root, no wrapping directory. Piped through
    # zstd rather than tar --zstd, which not every tar supports.
    tar -cf - -C "$src" . | zstd -q -19 -o "$out/$ASSET"
    # `sha256sum` format ("<hash>  <name>") so `shasum -a 256 -c` works on a
    # downloaded pair.
    (cd "$out" && shasum -a 256 "$ASSET" > "$ASSET.sha256")
    local sha
    sha="$(awk '{print $1}' "$out/$ASSET.sha256")"

    local tmp
    tmp="$(mktemp)"
    awk -v s="$sha" '/^SHA256=/ { print "SHA256=" s; next } { print }' "$PIN" > "$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "$PIN"
    echo "==> $out/$ASSET"
    echo "==> sha256 $sha written to $PIN; commit it."
}

upload() {
    [[ $# -ge 1 && $# -le 2 ]] || usage
    local out="$1" ref="${2:-}"
    load_pin
    [[ "$SHA256" != unpublished ]] || { echo "pin has no sha256; run pack first" >&2; exit 1; }
    [[ -f "$out/$ASSET" && -f "$out/$ASSET.sha256" ]] || { echo "no $ASSET(.sha256) in $out" >&2; exit 1; }

    local got
    got="$(sha_of "$out/$ASSET")"
    if [[ "$got" != "$SHA256" || "$(awk '{print $1}' "$out/$ASSET.sha256")" != "$SHA256" ]]; then
        echo "archive does not match the pin in $PIN" >&2
        echo "  pin:     $SHA256" >&2
        echo "  archive: $got" >&2
        exit 1
    fi

    local target=()
    [[ -z "$ref" ]] || target=(--target "$ref")
    read -r -p "Publish $ASSET ($SHA256) to $REPO as $TAG${ref:+ at $ref}? [y/N] " ans
    [[ "$ans" == [yY] ]] || { echo "aborted"; exit 1; }

    # --latest=false: this is data, so it must not become the repo's "Latest" release.
    "$GH" release create "$TAG" "$out/$ASSET" "$out/$ASSET.sha256" --repo "$REPO" \
        ${target[@]+"${target[@]}"} --latest=false --title "$TAG" \
        --notes "Anonymized medium benchmark fixture. Verify with: shasum -a 256 -c $ASSET.sha256"
    echo "==> Published $TAG"
}

case "${1:-}" in
pack) shift; pack "$@" ;;
upload) shift; upload "$@" ;;
*) usage ;;
esac
