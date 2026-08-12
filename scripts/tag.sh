#!/usr/bin/env bash
# Cut a release tag — but only if the tag's claim is true.
#
# WHAT A TAG MEANS HERE (CONVENTIONS §8). Not "the API is stable" and not "the
# collection is version X". It means exactly one thing: EVERY MODULE PASSED
# EVERY LANE AT THIS COMMIT. That is a checkable claim, so this script checks it
# instead of asking you to remember.
#
# WHY NOT SEMVER. Zig resolves dependencies by URL + hash; nothing reads a
# version string, so a semver tag on a 224-module collection is pure signalling
# with no mechanism behind it — and the signal would be false, since one number
# cannot describe modules that range from externally anchored to never consumed.
# A consumer who uses three modules learns nothing from "the collection went
# 2.0"; they learn what they need from those modules' CHANGELOG entries. So the
# tag carries the one fact it can carry honestly: a date, and a green gate.
#
#   usage: scripts/tag.sh [--dry-run] [YYYY-MM-DD]
#
# With no date, today's. A second tag on the same day gets a `.1`, `.2`, … so
# the name stays sortable and never collides.
#
# This script does NOT push. Pushing is the owner's decision, always.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

dry_run=0
date_arg=""
for a in "$@"; do
    case "$a" in
        --dry-run) dry_run=1 ;;
        -h | --help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *) date_arg="$a" ;;
    esac
done

day="${date_arg:-$(date +%Y-%m-%d)}"
if [[ ! "$day" =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "tag.sh: '$day' is not a YYYY-MM-DD date" >&2
    exit 1
fi

# ── the tag must describe a commit, not a work in progress ──────────────────
if [[ -n "$(git status --porcelain)" ]]; then
    echo "tag.sh: working tree is dirty — a tag would describe something that is not committed" >&2
    git status --short >&2
    exit 1
fi
branch="$(git branch --show-current)"
if [[ "$branch" != "main" ]]; then
    echo "tag.sh: on branch '$branch', not main — release tags are cut from main (CONVENTIONS §8)" >&2
    exit 1
fi

# Pick a free name: 2026-08-12, then 2026-08-12.1, …
tag="$day"
n=1
while git rev-parse -q --verify "refs/tags/$tag" >/dev/null; do
    tag="$day.$n"
    n=$((n + 1))
done

head_sha="$(git rev-parse --short HEAD)"
echo "tag.sh: candidate tag '$tag' at $head_sha"
echo

# ── the gate, all four lanes, judged by exit code ───────────────────────────
#
# Four separate `test.sh all` runs rather than one, because that is what CI
# runs and what the tag claims. They are sequential: this is a release step,
# not an inner loop, and running them concurrently would make the wall-clock
# numbers meaningless while contending for the same build cache.
lanes=("" "-Dstrict-debug" "-Doptimize=ReleaseFast" "-Doptimize=ReleaseSafe")
failed=()
for lane in "${lanes[@]}"; do
    label="${lane:-default}"
    printf 'tag.sh: lane %-24s ... ' "$label"
    start=$(date +%s)
    if bash scripts/test.sh all $lane >"/tmp/ziglibs-tag-${label//[^a-zA-Z0-9]/_}.log" 2>&1; then
        printf 'OK   %ss\n' "$(($(date +%s) - start))"
    else
        printf 'FAILED %ss  (log: /tmp/ziglibs-tag-%s.log)\n' \
            "$(($(date +%s) - start))" "${label//[^a-zA-Z0-9]/_}"
        failed+=("$label")
    fi
done

echo
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "tag.sh: NOT tagging — ${#failed[@]} lane(s) red: ${failed[*]}" >&2
    echo "A tag here would assert something untrue. Fix the lane, then run this again." >&2
    exit 1
fi

echo "tag.sh: all ${#lanes[@]} lanes green at $head_sha"
if [[ $dry_run -eq 1 ]]; then
    echo "tag.sh: --dry-run, so no tag was created (would have been '$tag')"
    exit 0
fi

git tag -a "$tag" -m "$tag

Every module passed every lane at $head_sha: default, strict Debug,
ReleaseFast and ReleaseSafe. That is the whole claim — this is a dated
snapshot of the collection, not a semantic version. Per-module changes are
in each module's CHANGELOG; see CONVENTIONS §8."

echo "tag.sh: created '$tag'. Not pushed — that is the owner's call."
