#!/usr/bin/env bash
# Turns the checksum-verified upstream images into *customised* guests that
# actually have the prerequisites this repo's tests need — unprivileged, no
# sudo, no new host packages, nothing written outside scripts/vm/.
#
# Usage:
#   scripts/vm/provision.sh                 — both platforms, if their recipe changed
#   scripts/vm/provision.sh openwrt
#   scripts/vm/provision.sh debian
#   scripts/vm/provision.sh --force         — rebuild even on a cache hit
#   scripts/vm/provision.sh --recipe openwrt  — print the recipe + hash, build nothing
#
# ── one mechanism per platform, because the platforms are not alike ──────
#
#   openwrt — the official OpenWRT ImageBuilder. It is self-contained (ships
#             its own host toolchain under staging_dir/host/bin), runs
#             unprivileged, and *builds a new image from scratch* out of a
#             declarative package list. There is no "install into the running
#             image" story on OpenWRT worth having: the stock ext4 image has
#             no package manager state for the kmods we need and the kernel
#             modules must match the exact kernel vermagic anyway.
#
#   debian  — boot the real guest, run apt-get, poweroff. No ImageBuilder
#             equivalent exists, and the obvious offline tool
#             (libguestfs/virt-customize) needs /boot/vmlinuz-* readable,
#             which is root-only on this host; widening that is a privilege
#             change and out of scope. So the guest installs its own packages
#             over the serial console that already works, into a *copy* of
#             the verified image. See provision-debian.exp.
#
# ── caching ──────────────────────────────────────────────────────────────
#
# Keyed on the recipe hash (scripts/vm/recipe.sh), which is baked into the
# provisioned image's filename. Change a package list -> different hash ->
# different filename -> guaranteed miss -> rebuild. There is no code path
# that can serve an image built from a different package list, because that
# image is not at the name the current recipe resolves to.
#
# ── trust ────────────────────────────────────────────────────────────────
#
# Upstream artifacts are verified by fetch-images.sh (stage 1) and this
# script re-verifies the ImageBuilder tarball before extracting it. The
# images this script PRODUCES are stage 2: locally derived, not signed by
# anyone, and their sha256 is recorded in the .provenance sidecar purely for
# change detection. Never treat that number as an upstream guarantee.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/manifest.sh"
source "$SCRIPT_DIR/recipe.sh"

IMAGES_DIR="$SCRIPT_DIR/images"
WORK_DIR="$SCRIPT_DIR/work"
mkdir -p "$IMAGES_DIR" "$WORK_DIR"

FORCE=0
PRINT_RECIPE=0
REQUESTED=()
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --recipe) PRINT_RECIPE=1 ;;
        openwrt|debian) REQUESTED+=("$arg") ;;
        *) echo "provision.sh: unknown argument '$arg' (openwrt|debian|--force|--recipe)" >&2; exit 1 ;;
    esac
done
[[ ${#REQUESTED[@]} -eq 0 ]] && REQUESTED=(openwrt debian)

if [[ $PRINT_RECIPE -eq 1 ]]; then
    for p in "${REQUESTED[@]}"; do
        echo "── $p ──"
        recipe_text "$p"
        echo "recipe-sha256: $(recipe_hash "$p")"
        echo "image:         $(provisioned_image "$p")"
        if provisioned_ok "$p"; then echo "cached:        yes"; else echo "cached:        NO (would rebuild)"; fi
        echo
    done
    exit 0
fi

# write_provenance <platform> <image>
#
# The sidecar is the only place the derived checksum is ever written, and it
# says in plain text what that number is and is not. Everything above
# `derived-sha256` is reproducible from the manifest; that one line is not.
write_provenance() {
    local platform="$1" img="$2" prov
    prov="$(provenance_file "$img")"
    {
        echo "# LOCALLY DERIVED IMAGE — this file is provenance, not a signature."
        echo "#"
        echo "# The recipe below IS reproducible: anyone with the same manifest.sh"
        echo "# entries gets an equivalent image. The upstream-* checksum is a real"
        echo "# supply-chain guarantee, verified at download by fetch-images.sh."
        echo "#"
        echo "# 'derived-sha256' is NOT. It is this machine's build of that recipe."
        echo "# Nobody upstream signed it, it is not stable across hosts or dates,"
        echo "# and it must never be presented as an upstream-verified checksum. It"
        echo "# exists for one thing: noticing that the file changed underneath us."
        echo
        recipe_text "$platform"
        echo "recipe-sha256: $(recipe_hash "$platform")"
        echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "built-by: scripts/vm/provision.sh"
        echo "derived-sha256: $(sha256sum "$img" | awk '{print $1}')  # locally derived / change-detection only — NOT an upstream guarantee"
    } > "$prov"
    echo "provision: wrote $(basename "$prov")"
}

# ── openwrt: official ImageBuilder ───────────────────────────────────────
provision_openwrt() {
    local img prov
    img="$(provisioned_image openwrt)"
    if [[ $FORCE -eq 0 ]] && provisioned_ok openwrt; then
        echo "openwrt: cache HIT for recipe $(recipe_hash openwrt | cut -c1-12) — reusing $(basename "$img")"
        return 0
    fi
    echo "openwrt: cache MISS for recipe $(recipe_hash openwrt | cut -c1-12) — building"

    "$SCRIPT_DIR/fetch-images.sh" imagebuilder

    local tarball="$IMAGES_DIR/$VM_OPENWRT_IB_FILE"
    # Re-verify at use time, not just at download time: the file has been
    # sitting on disk since, and extracting it runs its makefiles.
    local got
    got="$(sha256sum "$tarball" | awk '{print $1}')"
    if [[ "$got" != "$VM_OPENWRT_IB_SHA256" ]]; then
        echo "provision: ImageBuilder tarball checksum changed since download — refusing to extract" >&2
        exit 1
    fi

    local ib_root="$WORK_DIR/ib"
    local ib_dir="$ib_root/${VM_OPENWRT_IB_FILE%.tar.zst}"
    mkdir -p "$ib_root"
    if [[ ! -f "$ib_dir/Makefile" ]]; then
        echo "openwrt: extracting ImageBuilder (~$(du -h "$tarball" | cut -f1))"
        tar -I zstd -xf "$tarball" -C "$ib_root"
    else
        echo "openwrt: reusing extracted ImageBuilder at $ib_dir"
    fi
    # ImageBuilder warns and falls back to /tmp without this.
    mkdir -p "$ib_dir/tmp"

    # `make clean` is the ImageBuilder's own target (drops build_dir/ and
    # bin/). Without it a previous recipe's bin/targets output could be
    # mistaken for this one's.
    echo "openwrt: make clean"
    ( cd "$ib_dir" && make clean >/dev/null 2>&1 ) || true

    echo "openwrt: make image PROFILE=$VM_OPENWRT_IB_PROFILE PACKAGES=\"${VM_OPENWRT_PACKAGES[*]}\""
    local buildlog="$WORK_DIR/provision-openwrt-build.log"
    if ! ( cd "$ib_dir" && make image \
            PROFILE="$VM_OPENWRT_IB_PROFILE" \
            PACKAGES="${VM_OPENWRT_PACKAGES[*]}" ) >"$buildlog" 2>&1; then
        echo "provision: ImageBuilder FAILED — see $buildlog" >&2
        tail -30 "$buildlog" >&2
        exit 1
    fi

    local built="$ib_dir/bin/targets/x86/64/$VM_OPENWRT_IB_ARTIFACT"
    if [[ ! -f "$built" ]]; then
        echo "provision: ImageBuilder produced no $VM_OPENWRT_IB_ARTIFACT — see $buildlog" >&2
        exit 1
    fi

    # Cross-check the build's own manifest: every requested package must
    # actually be in the image. ImageBuilder is happy to warn about an
    # unknown package name and carry on, which would otherwise ship a
    # "successful" image missing exactly the thing that was added.
    local mf="$ib_dir/bin/targets/x86/64/openwrt-25.12.4-x86-64-${VM_OPENWRT_IB_PROFILE}.manifest"
    if [[ -f "$mf" ]]; then
        local missing=()
        for p in "${VM_OPENWRT_PACKAGES[@]}"; do
            grep -q "^${p} " "$mf" || missing+=("$p")
        done
        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "provision: these requested packages are NOT in the built image: ${missing[*]}" >&2
            echo "           (ImageBuilder warns and continues on unknown names — see $buildlog)" >&2
            exit 1
        fi
        echo "openwrt: all ${#VM_OPENWRT_PACKAGES[@]} requested packages present in the build manifest"
        cp "$mf" "${img}.manifest"
    fi

    rm -f "$img.partial"
    gzip -dc "$built" > "$img.partial"
    mv "$img.partial" "$img"
    echo "openwrt: provisioned $(du -h "$img" | cut -f1) $(basename "$img")"
    write_provenance openwrt "$img"
}

# ── debian: boot the real guest and let it apt-get ───────────────────────
provision_debian() {
    local img
    img="$(provisioned_image debian)"
    if [[ $FORCE -eq 0 ]] && provisioned_ok debian; then
        echo "debian: cache HIT for recipe $(recipe_hash debian | cut -c1-12) — reusing $(basename "$img")"
        return 0
    fi
    echo "debian: cache MISS for recipe $(recipe_hash debian | cut -c1-12) — building"

    "$SCRIPT_DIR/fetch-images.sh" debian

    local stock="$IMAGES_DIR/$VM_DEBIAN_FILE"
    local tmp="$img.partial"
    rm -f "$tmp"
    # A full copy, not a qcow2 backing-file overlay: an overlay would bind
    # the provisioned image to the stock file's path forever, and any later
    # re-fetch of the stock image would corrupt it silently. 388 MB copies in
    # a couple of seconds; the coupling is not worth saving.
    echo "debian: copying verified stock image -> $(basename "$tmp")"
    cp "$stock" "$tmp"

    # An unpinned pip spec would make the recipe hash a lie: the same recipe
    # text would install different bytes tomorrow. Refuse before booting.
    local spec
    for spec in "${VM_DEBIAN_PIP[@]:-}"; do
        [[ -z "$spec" ]] && continue
        if [[ "$spec" != *"=="* ]]; then
            echo "provision: pip spec '$spec' is not pinned (name==version) — refusing" >&2
            echo "           the recipe hash must describe exactly what lands in the image" >&2
            exit 1
        fi
    done

    # A source slot with no checksum, no URL or a floating tag would make the
    # recipe hash a lie in exactly the way an unpinned pip spec would: the same
    # recipe text would build different bytes tomorrow. Refuse before booting.
    local rec name ver url sha
    for rec in "${VM_DEBIAN_SRC[@]:-}"; do
        [[ -z "$rec" ]] && continue
        IFS='|' read -r name ver url sha _ <<< "$rec"
        if [[ -z "$name" || -z "$ver" || -z "$url" || -z "$sha" ]]; then
            echo "provision: source spec '$rec' is missing a field (name|version|url|sha256|cmake-flags)" >&2
            exit 1
        fi
        if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
            echo "provision: source spec '$name' has no sha256 — refusing" >&2
            echo "           the recipe hash must describe exactly what lands in the image" >&2
            exit 1
        fi
    done

    local hash='$6$ziglibsvm$2WcZuPUB4TEmGwA.07rEyxkoXl.TTGBAGJBnUjWbJhfpEFQiFc08SdtJACCJGetmUIy5MIbNfFN/Zy.euXHIC1'
    local log="$WORK_DIR/provision-debian.log"
    echo "debian: booting (no -snapshot) to apt-get install ${VM_DEBIAN_PACKAGES[*]}"
    [[ ${#VM_DEBIAN_PIP[@]} -gt 0 ]] && echo "debian:   then pip install ${VM_DEBIAN_PIP[*]}"
    for rec in "${VM_DEBIAN_SRC[@]:-}"; do
        [[ -z "$rec" ]] && continue
        IFS='|' read -r name ver url sha _ <<< "$rec"
        echo "debian:   then build $name $ver from source ($url)"
    done
    # 2048 MB, not 1024: the source slot runs four g++ processes at once.
    local srcarg=""
    if [[ ${#VM_DEBIAN_SRC[@]} -gt 0 ]]; then
        srcarg="$(printf '%s\n' "${VM_DEBIAN_SRC[@]}")"
    fi
    if ! expect "$SCRIPT_DIR/provision-debian.exp" "$tmp" "$hash" 2048 "${VM_DEBIAN_PACKAGES[*]}" "${VM_DEBIAN_PIP[*]:-}" "$srcarg" >"$log" 2>&1; then
        echo "provision: debian provisioning boot FAILED — see $log" >&2
        tail -30 "$log" >&2
        rm -f "$tmp"
        exit 1
    fi

    # The guest's own exit code for the apt batch. Without this check a
    # network hiccup or a typo'd package name would leave a perfectly
    # bootable image with nothing installed — a failure that looks exactly
    # like success from the outside.
    local exit_line
    exit_line="$(grep -o 'PROVISION_EXIT=[0-9]*' "$log" | tail -1 || true)"
    if [[ -z "$exit_line" ]]; then
        echo "provision: never saw PROVISION_EXIT= in the guest transcript — see $log" >&2
        rm -f "$tmp"
        exit 1
    fi
    if [[ "${exit_line#PROVISION_EXIT=}" != "0" ]]; then
        echo "provision: guest apt-get failed ($exit_line) — see $log" >&2
        sed -n '/===VM_CMD_BEGIN===/,/===VM_CMD_END===/p' "$log" | tail -30 >&2
        rm -f "$tmp"
        exit 1
    fi

    mv "$tmp" "$img"
    echo "debian: provisioned $(du -h "$img" | cut -f1) $(basename "$img")"
    write_provenance debian "$img"
}

for name in "${REQUESTED[@]}"; do
    case "$name" in
        openwrt) provision_openwrt ;;
        debian) provision_debian ;;
    esac
done

echo
echo "provision: done. Stale provisioned images from older recipes (safe to delete):"
for name in "${REQUESTED[@]}"; do
    while IFS= read -r f; do
        [[ -n "$f" ]] && echo "  $f"
    done < <(list_stale_provisioned "$name")
done
