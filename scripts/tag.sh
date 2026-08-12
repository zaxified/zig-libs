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
#   usage: scripts/tag.sh [--dry-run] [--all-lanes] [YYYY-MM-DD]
#
# With no date, today's. A second tag on the same day gets a `.1`, `.2`, … so
# the name stays sortable and never collides.
#
# This script does NOT push. Pushing is the owner's decision, always.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

dry_run=0
all_lanes=0
date_arg=""
for a in "$@"; do
    case "$a" in
        --dry-run) dry_run=1 ;;
        --all-lanes) all_lanes=1 ;;
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
# Logs go beside the build cache, not into /tmp. `/tmp` is not dependable
# here — the first real run of this script lost three of four lane logs to it
# and left the fourth as 1509 bytes of nothing, so an hour of gate time
# produced a refusal nobody could explain. Under `.zig-cache/` they sit next
# to the build they describe and are already gitignored.
LOG_DIR=".zig-cache/tag-logs"
mkdir -p "$LOG_DIR"

# ORDER IS DELIBERATE, and it is not about cache reuse — there is none to have.
# `heavy_optimize` (build.zig) substitutes ReleaseSafe for Debug on the heavy
# modules, which makes the DEFAULT lane's every (module, mode) pair a subset of
# strict-debug's and ReleaseSafe's. Those three therefore share artifacts; the
# three below share nothing at all, since each names one mode for every module.
# No ordering can save a single compile between them.
#
# So the order optimises TIME TO FIRST FAILURE instead:
#   ReleaseSafe  first — optimisations AND safety checks, the combination that
#                        caught the only real defect of 2026-08-12 while Debug
#                        and ReleaseFast both passed it by luck.
#   ReleaseFast  next  — same optimisations, no checks.
#   strict-debug last  — structurally the most expensive, since it is the one
#                        lane that builds the heavy modules in real Debug.
#
# The default lane is absent on purpose: it has no (module, mode) pair the
# other two do not already cover. Locally it is nearly free to add after them
# — its artifacts are already built — but it proves nothing new, so it is not
# worth the test-run time here.
lanes=("-Doptimize=ReleaseSafe" "-Doptimize=ReleaseFast" "-Dstrict-debug")
failed=()
for lane in "${lanes[@]}"; do
    label="${lane:-default}"
    log="$LOG_DIR/${label//[^a-zA-Z0-9]/_}.log"
    printf 'tag.sh: lane %-24s ... ' "$label"
    start=$(date +%s)
    if bash scripts/test.sh all $lane >"$log" 2>&1; then
        printf 'OK   %ss\n' "$(($(date +%s) - start))"
    else
        printf 'FAILED %ss\n' "$(($(date +%s) - start))"
        failed+=("$label")
        # The reason belongs HERE, not in a file the reader has to go find.
        # A refusal you cannot explain is barely better than no refusal.
        printf '\n  ── why %s failed (last 25 lines of %s) ──\n' "$label" "$log"
        if [[ -s "$log" ]]; then
            sed 's/^/  | /' <<<"$(tail -25 "$log")"
        else
            printf '  | (the lane wrote NO output — that is itself the finding:\n'
            printf '  |  the gate died before it could say anything)\n'
        fi
        printf '\n'
        # Stop at the first red lane unless asked otherwise. The 2026-08-12
        # run spent 2053 s on ReleaseFast and 587 s on ReleaseSafe AFTER
        # strict-debug had already failed — 44 minutes producing a verdict
        # that was going to be discarded, because a red lane means fixing and
        # re-running anyway.
        if [[ $all_lanes -eq 0 ]]; then
            printf 'tag.sh: stopping at the first red lane (--all-lanes to run them all)\n\n'
            break
        fi
    fi
done

echo
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "tag.sh: NOT tagging — ${#failed[@]} lane(s) red: ${failed[*]}" >&2
    echo "Reasons are printed above; full logs in $LOG_DIR/." >&2
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
