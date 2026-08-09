# Recipe hashing for provisioned VM images. Sourced by provision.sh and
# run.sh — not executable on its own. Requires manifest.sh to be sourced
# first (or sources it itself if it hasn't been).
#
# ── why a recipe hash and not an image checksum ──────────────────────────
#
# scripts/vm/fetch-images.sh pins an upstream SHA-256/512 for every artifact
# it downloads, and that IS a supply-chain guarantee: somebody else built the
# bytes, published a checksum, and we refuse to boot anything that doesn't
# match. Stage 1.
#
# The moment provision.sh installs packages into one of those images, that
# guarantee stops applying to the result. The derived image's own SHA-256 is
# not reproducible in any useful sense (build timestamps, apk/apt ordering,
# mirror state, filesystem allocation all move it) and nobody upstream has
# ever signed it. Recording it as if it were an upstream checksum would
# misrepresent where the trust comes from.
#
# What IS stable and checkable is the RECIPE:
#
#     recipe-version + platform + upstream artifact checksum + package list
#
# "package list" is three slots on debian, not one: apt names, pinned pip
# specs, and pinned from-source builds (URL + tag + sha256 + cmake flags).
# All three go into the text below verbatim. A from-source build that was NOT
# in the hash would be the one way to change what an image contains without
# changing its name — exactly the silent-cache-hit failure this file exists
# to prevent — so the third slot is hashed on the same terms as the other two.
#
# Two hosts running the same recipe get equivalent images; a changed package
# list is a changed recipe. So the recipe hash — not the image hash — is the
# cache key, and it is baked into the provisioned image's *filename*. A stale
# provisioned image therefore cannot be served by accident: it lives under a
# different name than the one the current recipe asks for.
#
# The derived image's own sha256 is still recorded, in the `.provenance`
# sidecar, explicitly labelled as locally-derived/change-detection-only. It
# answers "did this file change under me?", never "is this file trustworthy?".
#
# ── canonicalisation ─────────────────────────────────────────────────────
#
# The package list goes into the recipe text VERBATIM, in the order it is
# written in manifest.sh — not sorted. Sorting would make a reordering a
# no-op, which is the right semantics for the package manager but the wrong
# semantics for "did a human change the list?". Erring toward an extra
# rebuild is cheap; erring toward a silent cache hit is the failure mode this
# whole mechanism exists to prevent.

_RECIPE_SH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${VM_RECIPE_VERSION:-}" ]]; then
    source "$_RECIPE_SH_DIR/manifest.sh"
fi
VM_IMAGES_DIR="$_RECIPE_SH_DIR/images"

# recipe_text <platform> — the canonical, human-readable recipe. This exact
# text is what gets hashed, and it is copied verbatim into the .provenance
# sidecar so a reader can recompute the hash by hand.
recipe_text() {
    local platform="$1"
    case "$platform" in
        openwrt)
            printf 'recipe-version: %s\n' "$VM_RECIPE_VERSION"
            printf 'platform: openwrt\n'
            printf 'mechanism: openwrt-imagebuilder\n'
            printf 'upstream-artifact: %s\n' "$VM_OPENWRT_IB_FILE"
            printf 'upstream-sha256: %s\n' "$VM_OPENWRT_IB_SHA256"
            printf 'profile: %s\n' "$VM_OPENWRT_IB_PROFILE"
            printf 'image-artifact: %s\n' "$VM_OPENWRT_IB_ARTIFACT"
            local p
            for p in "${VM_OPENWRT_PACKAGES[@]}"; do
                printf 'package: %s\n' "$p"
            done
            ;;
        debian)
            printf 'recipe-version: %s\n' "$VM_RECIPE_VERSION"
            printf 'platform: debian\n'
            printf 'mechanism: boot-and-apt\n'
            printf 'upstream-artifact: %s\n' "$VM_DEBIAN_FILE"
            printf 'upstream-sha512: %s\n' "$VM_DEBIAN_SHA512"
            local p
            for p in "${VM_DEBIAN_PACKAGES[@]}"; do
                printf 'package: %s\n' "$p"
            done
            # pip specs are part of the recipe for the same reason apt names
            # are: they change what is installed in the image. They are
            # required to be `name==version` (manifest.sh), so this stays a
            # fact about the image and not a fact about the day it was built.
            for p in "${VM_DEBIAN_PIP[@]:-}"; do
                [[ -z "$p" ]] && continue
                printf 'pip: %s\n' "$p"
            done
            # From-source builds are part of the recipe for the same reason
            # apt names and pip pins are — more so, in fact: an unhashed
            # source pin would let the same recipe text produce an image
            # carrying a different library. Every field is printed, one per
            # line, so a reader can see exactly what was built and recompute
            # the hash by hand. The build PROCEDURE that consumes these fields
            # lives in provision-debian.exp and is covered by
            # recipe-version above.
            local s name ver url sha flags
            for s in "${VM_DEBIAN_SRC[@]:-}"; do
                [[ -z "$s" ]] && continue
                IFS='|' read -r name ver url sha flags <<< "$s"
                printf 'src: %s %s\n' "$name" "$ver"
                printf 'src-url: %s\n' "$url"
                printf 'src-sha256: %s\n' "$sha"
                printf 'src-cmake: %s\n' "$flags"
            done
            ;;
        *)
            echo "recipe.sh: unknown platform '$platform'" >&2
            return 1
            ;;
    esac
}

# recipe_hash <platform> — sha256 of recipe_text, full 64 hex chars.
recipe_hash() {
    recipe_text "$1" | sha256sum | awk '{print $1}'
}

# provisioned_image <platform> — path the current recipe's provisioned image
# must live at. The 12-hex recipe prefix in the name is what makes a stale
# image unreachable rather than silently reused.
provisioned_image() {
    local platform="$1" h
    h="$(recipe_hash "$platform")" || return 1
    case "$platform" in
        openwrt) printf '%s/openwrt-25.12.4-x86-64-ext4-prov-%s.img\n' "$VM_IMAGES_DIR" "${h:0:12}" ;;
        debian)  printf '%s/debian-13-nocloud-amd64-prov-%s.qcow2\n' "$VM_IMAGES_DIR" "${h:0:12}" ;;
    esac
}

# provenance_file <image-path>
provenance_file() { printf '%s.provenance\n' "$1"; }

# provisioned_ok <platform> — true when the image for the CURRENT recipe
# exists and its sidecar agrees about the recipe hash. Deliberately does not
# re-verify the derived sha256: that would turn a change-detection aid into a
# gate, and any legitimate rebuild would then look like tampering.
provisioned_ok() {
    local platform="$1" img prov want got
    img="$(provisioned_image "$platform")" || return 1
    [[ -f "$img" ]] || return 1
    prov="$(provenance_file "$img")"
    [[ -f "$prov" ]] || return 1
    want="$(recipe_hash "$platform")"
    got="$(awk '/^recipe-sha256:/{print $2}' "$prov")"
    [[ "$want" == "$got" ]]
}

# list_stale_provisioned <platform> — provisioned images present for some
# OTHER recipe. Used to tell "never provisioned" apart from "recipe moved",
# which are the same symptom but very different mistakes.
list_stale_provisioned() {
    local platform="$1" cur f
    cur="$(provisioned_image "$platform")"
    case "$platform" in
        openwrt) set -- "$VM_IMAGES_DIR"/openwrt-*-prov-*.img ;;
        debian)  set -- "$VM_IMAGES_DIR"/debian-*-prov-*.qcow2 ;;
    esac
    for f in "$@"; do
        [[ -f "$f" ]] || continue
        [[ "$f" == "$cur" ]] && continue
        printf '%s\n' "$f"
    done
}
