#!/usr/bin/env bash
# Cut a release tag — but only if the tag's claim is true.
#
# WHAT A TAG MEANS HERE (CONVENTIONS §8). Not "the API is stable" and not "the
# collection is version X". It means exactly one thing: EVERY MODULE PASSED
# EVERY LANE AT THIS COMMIT. That is a checkable claim, so this script checks it
# instead of asking you to remember.
#
# ⚠ ONE PIPELINE, AND THIS SCRIPT IS ITS SECOND STEP (owner, 2026-08-24):
#
#   the owner asks for a tag -> this script cuts it, it is pushed
#                            -> pushing a tag runs the FULL matrix on the tag ref
#                            -> green: a Release is cut from this tag's message
#                            -> red:   no Release, and the tag is WITHDRAWN
#
# So the MATRIX IS THE AUTHORITY, and this script runs no lane of its own
# (since 2026-09-18). It refuses unless CI already passed on this commit, which
# costs a second; the local lanes it used to run first were amd64-only, repeated
# work the matrix then did again, and could not see what the arm64 lane found in
# `montint` on 2026-08-24. Tag `2026-08-18` was cut on three green local lanes,
# pushed, and deleted when the matrix went red on ReleaseFast amd64 -- the
# local pre-check was never what made a tag true.
#
# The Release is not cut from here: this script and CI both hold no
# `contents: write`, on purpose. It is cut by hand from the tag's own message
# once the matrix is green.
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

# ⭐ THE LANES RUN IN CI, NOT HERE (2026-09-18). This script used to run the
# full gate locally in two optimize modes before cutting the tag, and the tag
# push then ran the whole matrix again in CI -- the same work twice, the local
# half amd64-only and so never the authority anyway. Now the one question asked
# here is the one that can be answered in a second: did CI pass on THIS commit?
# The tag push then runs every lane, and the stamps (scripts/test.sh) make it
# re-test only what no green lane has already proven at its fingerprint.
#
# `gh` is looked up on PATH, which is also how scripts/lib/test-tag.sh replaces it.
# A DRY-RUN CI proves the pipeline and nothing about the code (see the
# ZIGLIBS_DRY_RUN block at the top of ci.yml), so its green is not a tag's.
if git show HEAD:.github/workflows/ci.yml 2>/dev/null | grep -qE '^\s*ZIGLIBS_DRY_RUN:\s*"?1"?\s*$'; then
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

# ── example-apps pins ────────────────────────────────────────────────────────
# The apps under example-apps/ pin zig-libs by tag, because that is what a
# person who downloads one needs. Bump them to the tag being cut, so a copy
# taken from tag T is built against T rather than against T-1.
#
# Only possible because example-apps/ is OUTSIDE `.paths`: editing an app does
# not change the package hash, so the hash written here stays correct after the
# very commit that writes it. Verified by hashing a clean export with and
# without an example-apps/ tree — identical.
#
# Only the FIRST .url/.hash pair is touched. That is the live pin; the
# commented `#main` / `#<commit>` alternatives below it are left as written.
bump_app_pins() {
    local newtag="$1" export_dir pkg_hash z
    [ -d example-apps ] || return 0
    # Off tmpfs: this extracts a full ~54 MB repo archive, and /tmp is RAM here
    # (the house rule that closed a prior OOM). test.sh redirects TMPDIR for its
    # own children but does not run this; `.zig-cache` is the repo's scratch.
    mkdir -p .zig-cache
    export_dir="$(mktemp -d "$PWD/.zig-cache/tag-export.XXXXXX")"
    git archive HEAD | tar -x -C "$export_dir"
    if ! pkg_hash="$(zig fetch "$export_dir" 2>/dev/null)"; then
        echo "tag.sh: could not compute the package hash — example-apps pins NOT bumped" >&2
        rm -rf "$export_dir"
        return 1
    fi
    rm -rf "$export_dir"
    for z in example-apps/*/build.zig.zon; do
        [ -f "$z" ] || continue
        oldtag="$(sed -n 's|.*zig-libs#\([0-9][-0-9.]*\)".*|\1|p' "$z" | head -1)"
        sed -i "0,/zig-libs#/{s|\(zig-libs#\)[^\"]*|\1$newtag|}" "$z"
        sed -i "0,/\.hash = /{s|\(\.hash = \"\)[^\"]*|\1$pkg_hash|}" "$z"
        # The README's download URL names the same tag; check-apps.sh fails if
        # the two disagree, so they move together or not at all.
        #
        # ⚠ SCOPED to the tag's three real forms (`tags/…`, `zig-libs-…`,
        # `-b …`). A whole-file `s|$oldtag|$newtag|g` also rewrote prose that
        # merely shared the date — timecapsule's README says "publishes
        # 2026-08-24 19:35:15 UTC" as an example — silently corrupting it on
        # every tag cut.
        if [ -n "$oldtag" ] && [ -f "$(dirname "$z")/README.md" ]; then
            sed -i -E "s#(tags/|zig-libs-|-b )$oldtag#\\1$newtag#g" "$(dirname "$z")/README.md"
        fi
    done
    if ! git diff --quiet -- example-apps; then
        git add example-apps
        git commit -q -m "example-apps: pin $newtag" -m "Cut by scripts/tag.sh so a copy taken from this tag builds against this tag. example-apps/ is outside build.zig.zon's .paths, so this commit does not change the package hash it just wrote."
        echo "tag.sh: example-apps pins bumped to $newtag ($pkg_hash)"
    fi
}
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

# ⚠ THE DEFAULT MESSAGE IS A FLOOR, NOT A TEMPLATE TO SHIP AS-IS. CONVENTIONS
# §8: a tag message carries the BIG CHANGES since the previous tag, because
# that is the question a reader of a dated tag has. This script cannot write
# those -- it can count, and counting is the half that goes wrong: the
# `2026-08-24` message claimed "5 commits over 2026-08-19" where the range held
# 143, having counted the day's commits instead of the range. So the count
# below is computed, and the prose is left to whoever cuts the tag.
prev_tag="$(git tag -l '20*' --sort=-v:refname | grep -v "^$tag\$" | head -1)"
if [ -n "$prev_tag" ]; then
    n_commits="$(git rev-list --count "$prev_tag..HEAD")"
    range_line="Cut at $head_sha, $n_commits commits over $prev_tag."
else
    range_line="Cut at $head_sha."
fi

git tag -a "$tag" -m "$tag

$range_line Every module passed every CI lane at this commit (ReleaseSafe
and ReleaseFast on amd64, ReleaseSafe on arm64, examples, strict-Debug
compile) -- directly, or by a green stamp for its unchanged fingerprint.
A red matrix on this tag withdraws it. That is the whole claim — this
is a dated snapshot of the collection, not a semantic version. Per-module
changes are in each module's CHANGELOG; see CONVENTIONS §8.

WHAT CHANGED SINCE $prev_tag: <<< fill this in before pushing -- CONVENTIONS §8.
New modules, campaigns that touched everything, defect classes closed, APIs that
moved. Any number here is a claim: count it, do not estimate it. >>>"

echo "tag.sh: created '$tag'. Not pushed — that is the owner's call."
