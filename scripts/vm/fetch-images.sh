#!/usr/bin/env bash
# Fetches (or reuses) the VM images pinned in manifest.sh, verifying a
# checksum on every one — an unverified image would then be booted and
# executed as root, which is a supply-chain hole, not a convenience to skip.
# A checksum mismatch deletes the partial file and aborts loudly; it never
# leaves a bad file sitting in scripts/vm/images/ for a later run to trust.
#
# Usage:
#   scripts/vm/fetch-images.sh              — fetch everything below if missing
#   scripts/vm/fetch-images.sh openwrt      — just one
#   scripts/vm/fetch-images.sh debian
#   scripts/vm/fetch-images.sh imagebuilder — the OpenWRT ImageBuilder tarball
#   scripts/vm/fetch-images.sh --force      — re-fetch even if present
#
# Images land in scripts/vm/images/ (git-ignored — see .gitignore). Never
# committed: the OpenWRT image alone is ~126 MB, more than 4x the repo's
# entire .git today.
#
# THIS SCRIPT ONLY EVER HANDLES STAGE-1 (upstream, checksum-pinned)
# ARTIFACTS. Turning them into customised guests is scripts/vm/provision.sh's
# job, and its outputs are explicitly NOT upstream-verifiable — see the
# two-stage trust note at the top of manifest.sh. A fresh clone reproduces
# everything with:
#
#   scripts/vm/fetch-images.sh && scripts/vm/provision.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/manifest.sh"

IMAGES_DIR="$SCRIPT_DIR/images"
mkdir -p "$IMAGES_DIR"

FORCE=0
REQUESTED=()
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        *) REQUESTED+=("$arg") ;;
    esac
done
[[ ${#REQUESTED[@]} -eq 0 ]] && REQUESTED=("${VM_IMAGE_NAMES[@]}")

verify_sha256() {
    local file="$1" want="$2"
    local got
    got="$(sha256sum "$file" | awk '{print $1}')"
    [[ "$got" == "$want" ]]
}

verify_sha512() {
    local file="$1" want="$2"
    local got
    got="$(sha512sum "$file" | awk '{print $1}')"
    [[ "$got" == "$want" ]]
}

# fetch_one <dest_path> <url>
fetch_one() {
    local dest="$1" url="$2"
    echo "  fetching $url"
    if ! curl -fSL --retry 3 --retry-delay 2 -o "$dest.partial" "$url"; then
        echo "fetch-images: download FAILED: $url" >&2
        rm -f "$dest.partial"
        exit 1
    fi
    mv "$dest.partial" "$dest"
}

fetch_openwrt() {
    local dest="$IMAGES_DIR/$VM_OPENWRT_FILE"
    if [[ -f "$dest" && $FORCE -eq 0 ]]; then
        if verify_sha256 "$dest" "$VM_OPENWRT_SHA256"; then
            echo "openwrt: already present and verified ($dest)"
            return 0
        fi
        echo "openwrt: present but checksum mismatch — re-fetching" >&2
        rm -f "$dest"
    fi

    if [[ -n "$VM_OPENWRT_LOCAL_REUSE" && -f "$VM_OPENWRT_LOCAL_REUSE" && $FORCE -eq 0 ]]; then
        echo "openwrt: reusing local copy at $VM_OPENWRT_LOCAL_REUSE"
        cp "$VM_OPENWRT_LOCAL_REUSE" "$dest.partial"
        if ! verify_sha256 "$dest.partial" "$VM_OPENWRT_SHA256"; then
            echo "fetch-images: local reuse copy FAILED checksum verification — deleting, falling back to download" >&2
            rm -f "$dest.partial"
        else
            mv "$dest.partial" "$dest"
            echo "openwrt: verified (sha256 matches manifest)"
            return 0
        fi
    fi

    local gz="$IMAGES_DIR/${VM_OPENWRT_FILE}.gz"
    fetch_one "$gz" "$VM_OPENWRT_URL"
    if ! verify_sha256 "$gz" "$VM_OPENWRT_GZ_SHA256"; then
        echo "fetch-images: openwrt .gz SHA-256 MISMATCH — deleting partial file, refusing to boot an unverified image" >&2
        rm -f "$gz"
        exit 1
    fi
    echo "openwrt: .gz checksum verified, decompressing"
    rm -f "$dest"  # gzip -k refuses to overwrite; without this a stale/wrong
                   # $dest from an earlier run would silently survive a
                   # --force re-fetch and still "verify" (it was already
                   # correct before) — verified this was a real bug, not
                   # hypothetical, by hitting it.
    gzip -dk "$gz"
    rm -f "$gz"
    if ! verify_sha256 "$dest" "$VM_OPENWRT_SHA256"; then
        echo "fetch-images: openwrt decompressed image SHA-256 MISMATCH — deleting, refusing to boot an unverified image" >&2
        rm -f "$dest"
        exit 1
    fi
    echo "openwrt: verified (sha256 matches manifest)"
}

fetch_debian() {
    local dest="$IMAGES_DIR/$VM_DEBIAN_FILE"
    if [[ -f "$dest" && $FORCE -eq 0 ]]; then
        if verify_sha512 "$dest" "$VM_DEBIAN_SHA512"; then
            echo "debian: already present and verified ($dest)"
            return 0
        fi
        echo "debian: present but checksum mismatch — re-fetching" >&2
        rm -f "$dest"
    fi

    fetch_one "$dest" "$VM_DEBIAN_URL"
    if ! verify_sha512 "$dest" "$VM_DEBIAN_SHA512"; then
        echo "fetch-images: debian SHA-512 MISMATCH — deleting partial file, refusing to boot an unverified image" >&2
        rm -f "$dest"
        exit 1
    fi
    echo "debian: verified (sha512 matches manifest)"
}

# The OpenWRT ImageBuilder tarball. Verified exactly like the stock images:
# its SHA-256 comes from the same published `sha256sums` in the same pinned
# release directory. This is still stage 1 — it's an artifact OpenWRT built
# and published. What provision.sh then *makes* with it is stage 2.
fetch_imagebuilder() {
    local dest="$IMAGES_DIR/$VM_OPENWRT_IB_FILE"
    if [[ -f "$dest" && $FORCE -eq 0 ]]; then
        if verify_sha256 "$dest" "$VM_OPENWRT_IB_SHA256"; then
            echo "imagebuilder: already present and verified ($dest)"
            return 0
        fi
        echo "imagebuilder: present but checksum mismatch — re-fetching" >&2
        rm -f "$dest"
    fi

    fetch_one "$dest" "$VM_OPENWRT_IB_URL"
    if ! verify_sha256 "$dest" "$VM_OPENWRT_IB_SHA256"; then
        echo "fetch-images: imagebuilder SHA-256 MISMATCH — deleting partial file, refusing to build an image from unverified sources" >&2
        rm -f "$dest"
        exit 1
    fi
    echo "imagebuilder: verified (sha256 matches manifest)"
}

for name in "${REQUESTED[@]}"; do
    case "$name" in
        openwrt) fetch_openwrt ;;
        debian) fetch_debian ;;
        imagebuilder) fetch_imagebuilder ;;
        *)
            echo "fetch-images: unknown image '$name' (known: ${VM_IMAGE_NAMES[*]})" >&2
            exit 1
            ;;
    esac
done
