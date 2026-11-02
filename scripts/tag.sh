#!/usr/bin/env bash
# Cut a release tag — but only if the tag's claim is true.
#
# WHAT A TAG MEANS HERE (CONVENTIONS §8). Not "the API is stable" and not "the
# collection is version X". It means exactly one thing: EVERY MODULE PASSED
# EVERY LANE AT THIS COMMIT. That is a checkable claim, so this script checks it
# instead of asking you to remember.
#
# ⚠ THE BY-HAND ROUTE (since 2026-11-02). Tags are normally cut by the scheduled
# CI run, which tags the commit it tested and publishes the Release itself (ci.yml
# `release-*`, scripts/lib/auto-release.sh, CONVENTIONS §8). This script remains
# for when the owner wants a tag between runs:
#
#   this script cuts it, on main -> the owner pushes it
#                                -> pushing a tag runs the FULL matrix on the tag ref
#                                -> green: a Release is cut by hand from this tag's message
#                                -> red:   no Release, and the tag is WITHDRAWN
#
# So the MATRIX IS THE AUTHORITY, and this script runs no lane of its own
# (since 2026-09-18). It refuses unless CI already passed on this commit, which
# costs a second; the local lanes it used to run first were amd64-only, repeated
# work the matrix then did again, and could not see what the arm64 lane found in
# `montint` on 2026-08-24. Tag `2026-08-18` was cut on three green local lanes,
# pushed, and deleted when the matrix went red on ReleaseFast amd64 -- the
# local pre-check was never what made a tag true.
#
# WHY NOT SEMVER. Zig resolves dependencies by URL + hash; nothing reads a
# version string, so a semver tag on a 225-module collection is pure signalling
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
# shellcheck source=scripts/lib/tag-lib.sh
source scripts/lib/tag-lib.sh

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
tag="$(free_tag_name "$day")"

head_sha="$(git rev-parse --short HEAD)"
echo "tag.sh: candidate tag '$tag' at $head_sha"
echo

# ⭐ THE LANES RUN IN CI, NOT HERE (2026-09-18). This script used to run the
# full gate locally in two optimize modes before cutting the tag, and the tag
# push then ran the whole matrix again in CI -- the same work twice, the local
# half amd64-only and so never the authority anyway. Now the one question asked
# here is the one that can be answered in a second: did CI pass on THIS commit?
# The tag push then runs every lane, and the stamps (scripts/test.sh) make it
# re-test only what no green lane has already proven at its fingerprint.
#
# `gh` is looked up on PATH, which is also how scripts/lib/test-tag.sh replaces it.
if ci_dry_run_on HEAD; then
    echo "tag.sh: NOT tagging — ci.yml at HEAD has ZIGLIBS_DRY_RUN on, so CI tested nothing." >&2
    echo "Turn it off, push, let CI pass for real, then tag." >&2
    exit 1
fi
full_sha="$(git rev-parse HEAD)"
verdict="$(gh run list --workflow ci.yml --branch main --event push --commit "$full_sha" \
    --limit 1 --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"' 2>/dev/null)" || verdict=""
case "$verdict" in
    "completed success")
        echo "tag.sh: CI passed on $head_sha"
        ;;
    "" | "null null")
        echo "tag.sh: NOT tagging — no CI run on main for $head_sha." >&2
        echo "Push it and let CI finish; the tag asserts what CI proved, not what was hoped." >&2
        exit 1
        ;;
    completed\ *)
        echo "tag.sh: NOT tagging — CI on $head_sha concluded '${verdict#completed }'." >&2
        exit 1
        ;;
    *)
        echo "tag.sh: NOT tagging — CI on $head_sha is still '${verdict%% *}'. Wait for it." >&2
        exit 1
        ;;
esac
if [[ $dry_run -eq 1 ]]; then
    echo "tag.sh: --dry-run, so no tag was created (would have been '$tag')"
    exit 0
fi

# ── example-apps pins (scripts/lib/tag-lib.sh) ────────────────────────────────
if [ "${dry_run:-0}" != 1 ]; then
    # ⭐ FATAL, deliberately. This used to be `|| true`, which swallowed the
    # function's one failure path -- `zig fetch` not producing a package hash --
    # and cut the tag anyway. The result would have been a released tag whose
    # example-apps still pin the PREVIOUS one, carried under a tag message that
    # says every module passed every lane. Nothing downstream could catch it
    # either: `check-apps.sh` builds the apps with `--fork` against the working
    # tree, never against the pin, and the README/manifest agreement check stays
    # happy because both halves stayed on the old tag together.
    #
    # A tag that cannot be cut correctly is better than one that is wrong.
    if ! bump_app_pins "$tag"; then
        echo "tag.sh: refusing to cut '$tag' — example-apps pins could not be bumped (see above)" >&2
        exit 1
    fi
    head_sha="$(git rev-parse HEAD)"
fi

# The message is the generated notes (scripts/lib/release-notes.py), the same text
# a scheduled tag carries: CONVENTIONS §8, any number in it is computed.
prev_tag="$(newest_date_tag)"
if ! create_notes_tag "$tag" "$prev_tag" HEAD scripts/lib; then
    echo "tag.sh: could not create '$tag'" >&2
    exit 1
fi

echo "tag.sh: created '$tag'. Not pushed — that is the owner's call."
