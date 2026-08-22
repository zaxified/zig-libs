#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regenerate (or verify) modules/tz/src/tz_data.zig from a PINNED IANA tzdata
# release, instead of from whatever this machine happens to have installed.
#
# Why this exists: tz-gen reads a compiled zoneinfo tree, and the obvious tree
# to hand it is /usr/share/zoneinfo. That tree is the output of the DISTRO's
# zic run, so its tzdata release is whatever the distro shipped -- on this
# host, 2026c against a table pinned at 2026a. The claim in tz's SPEC.md and
# README that "the pin can be re-derived, not just trusted" was therefore only
# true on a machine that happened to have the right release installed. This
# script fetches the pinned release, compiles it with the system zic, and
# hands THAT tree to tz-gen, so the claim holds anywhere.
#
#   ./fetch-and-build.sh            regenerate modules/tz/src/tz_data.zig
#   ./fetch-and-build.sh --check    regenerate to a temp file and diff; exit 1
#                                   if the committed table does not match
#   ./fetch-and-build.sh 2026c      use a different release (see checksums)
#
# Failure is always loud. In particular this never falls back to the host's
# /usr/share/zoneinfo: a silent fall-back would produce a table that looks
# regenerated and is not, which is the exact failure mode this replaces.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
committed="$repo/modules/tz/src/tz_data.zig"

check_only=0
release=""
for arg in "$@"; do
    case "$arg" in
        --check) check_only=1 ;;
        -h|--help) sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        -*) echo "tz-gen: unknown option $arg" >&2; exit 2 ;;
        *) release="$arg" ;;
    esac
done

# The release is the committed table's own header, so the script and the pin
# cannot drift apart: bumping one without the other is not expressible.
if [ -z "$release" ]; then
    release="$(sed -n 's/.*IANA tzdata \([0-9a-z]*\) (public domain).*/\1/p' "$committed" | head -1)"
    [ -n "$release" ] || { echo "tz-gen: cannot read the pinned release from $committed" >&2; exit 1; }
fi

tarball="tzdata${release}.tar.gz"
url="https://data.iana.org/time-zones/releases/$tarball"

# IANA publishes a detached PGP signature but no checksum file, so the hash is
# pinned here. That is the stronger of the two anyway: it names exact bytes,
# and verifying it needs no keyring.
expected="$(sed -n "s/^\\([0-9a-f]\\{64\\}\\)  $tarball\$/\\1/p" "$here/checksums.txt" || true)"
if [ -z "$expected" ]; then
    echo "tz-gen: no pinned SHA-256 for $tarball in scripts/tz-gen/checksums.txt." >&2
    echo "        Add one line '<sha256>  $tarball' after checking the release's" >&2
    echo "        PGP signature from https://data.iana.org/time-zones/releases/." >&2
    exit 1
fi

# zic is in /usr/sbin on Debian/Ubuntu, which is not on a non-root PATH.
# TZ_GEN_ZIC overrides the search (also how the failure path is tested).
zic="${TZ_GEN_ZIC:-$(command -v zic || true)}"
if [ -n "${TZ_GEN_ZIC:-}" ] && [ ! -x "$TZ_GEN_ZIC" ]; then
    echo "tz-gen: TZ_GEN_ZIC=$TZ_GEN_ZIC is not an executable." >&2
    exit 1
fi
for candidate in /usr/sbin/zic /sbin/zic /usr/local/sbin/zic; do
    [ -n "$zic" ] && break
    [ -x "$candidate" ] && zic="$candidate"
done
if [ -z "$zic" ]; then
    echo "tz-gen: zic not found (looked on PATH, /usr/sbin, /sbin, /usr/local/sbin)." >&2
    echo "        It ships in the 'tzdata' package on Debian/Ubuntu and" >&2
    echo "        'tzdata'/'tzcode' elsewhere. NOT falling back to" >&2
    echo "        /usr/share/zoneinfo: that tree is this machine's release," >&2
    echo "        which is the problem this script exists to solve." >&2
    exit 1
fi

command -v curl >/dev/null || { echo "tz-gen: curl not found" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "tz-gen: sha256sum not found" >&2; exit 1; }

# One directory per release. Not one shared directory: zic writes files but
# never removes them, so a zone dropped between two releases would survive
# into the next run's output and be silently emitted.
work="${TZ_GEN_WORK_DIR:-$repo/.zig-cache/tz-gen}/$release"
mkdir -p "$work"
zoneinfo="$work/zoneinfo"

cd "$work"
if [ ! -f "$tarball" ]; then
    echo "tz-gen: fetching $url"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$tarball.part" "$url"
    mv "$tarball.part" "$tarball"
fi

actual="$(sha256sum "$tarball" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
    echo "tz-gen: SHA-256 mismatch for $tarball" >&2
    echo "        expected $expected" >&2
    echo "        actual   $actual" >&2
    echo "        Refusing to build. Delete $work/$tarball and retry; if it" >&2
    echo "        still differs, the pin or the download is wrong -- do not" >&2
    echo "        'fix' this by updating checksums.txt to match." >&2
    exit 1
fi

mkdir -p src "$zoneinfo"
tar xzf "$tarball" -C src

# The same file set and the same -b mode a distro uses. `-b fat` matters: with
# `-b slim` zic omits the transitions that the POSIX-TZ footer can regenerate,
# and tz-gen reads transitions, so the emitted table would differ.
( cd src && "$zic" -b fat -d "$zoneinfo" \
    africa antarctica asia australasia europe northamerica southamerica \
    etcetera backward factory )

# zic emits no version marker; tz-gen reads `tzdata.zi` or `+VERSION`, and the
# tarball's `version` file is exactly the latter's content.
cp src/version "$zoneinfo/+VERSION"

if [ "$check_only" = 1 ]; then
    out="$work/tz_data.check.zig"
else
    out="$committed"
fi

( cd "$here" && zig build run -- "$out" "$zoneinfo" )
zig fmt "$out" >/dev/null

if [ "$check_only" = 1 ]; then
    if diff -u "$committed" "$out"; then
        echo "tz-gen: modules/tz/src/tz_data.zig reproduces from tzdata $release."
    else
        echo "tz-gen: the committed table does NOT match tzdata $release (diff above)." >&2
        exit 1
    fi
else
    echo "tz-gen: wrote $committed from tzdata $release."
fi
