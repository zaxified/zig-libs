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
# So THESE THREE LANES ARE A PRE-CHECK, NOT THE AUTHORITY. They are amd64-only:
# the arm64 lane that found x86 inline asm in `montint` on 2026-08-24 is not
# among them, and neither is any lane this host cannot run. What the tag asserts
# is what the MATRIX ran. Tag `2026-08-18` was cut on three green local lanes,
# pushed, and deleted when the matrix went red on ReleaseFast amd64 -- that is
# the pipeline working.
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
#   usage: scripts/tag.sh [--dry-run] [--all-lanes] [YYYY-MM-DD]
#
# With no date, today's. A second tag on the same day gets a `.1`, `.2`, … so
# the name stays sortable and never collides.
#
# This script does NOT push. Pushing is the owner's decision, always.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
source scripts/test-lib.sh   # for _zl_cap_argv (memory cap); see the lane loop below

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

# ── the gate, all three lanes, judged by exit code ──────────────────────────
#
# Three separate `test.sh all` runs rather than one, because that is what CI
# runs and what the tag claims. They are sequential: this is a release step,
# not an inner loop, and running them concurrently would make the wall-clock
# numbers meaningless while contending for the same build cache.
# Logs go beside the build cache, not into /tmp. `/tmp` is not dependable
# here — the first real run of this script (back when the gate still had a
# fourth, default lane) lost three of four lane logs to it
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
# Each entry is `<subcommand> <flags>`. Debug is COMPILE-ONLY, matching CI:
# nothing consumes this collection in Debug, so what that lane can honestly
# claim is that the code builds there — and running its tests was measured to
# prove nothing ReleaseSafe does not, while skipping fifteen that its siblings
# run. See `cmd_build` in scripts/test.sh.
lanes=("all -Doptimize=ReleaseSafe" "all -Doptimize=ReleaseFast" "build -Dstrict-debug")
failed=()
for lane in "${lanes[@]}"; do
    label="${lane:-default}"
    log="$LOG_DIR/${label//[^a-zA-Z0-9]/_}.log"
    printf 'tag.sh: lane %-24s ... ' "$label"
    start=$(date +%s)
    # Each lane runs INSIDE the memory cap, not beside it. `scripts/test.sh`
    # sources test-lib.sh but never calls `_zl_cap_argv`, so a bare
    # `test.sh all` is unbounded — and three of them in a row is what killed
    # a desktop here on 2026-08-18: the kernel OOM killer picks its victim by
    # size, and under an IDE that victim is the editor. Capping the lane means
    # a runaway dies as one red lane (exit 137) instead.
    _zl_cap_argv
    if ${_ZL_CAP[@]+"${_ZL_CAP[@]}"} bash scripts/test.sh $lane >"$log" 2>&1; then
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

$range_line Every module passed every release lane: ReleaseSafe and
ReleaseFast, and compiled in strict Debug. That is the whole claim — this
is a dated snapshot of the collection, not a semantic version. Per-module
changes are in each module's CHANGELOG; see CONVENTIONS §8.

WHAT CHANGED SINCE $prev_tag: <<< fill this in before pushing -- CONVENTIONS §8.
New modules, campaigns that touched everything, defect classes closed, APIs that
moved. Any number here is a claim: count it, do not estimate it. >>>"

echo "tag.sh: created '$tag'. Not pushed — that is the owner's call."
