#!/usr/bin/env bash
# Decide whether a CI lane's `.zig-cache` is worth saving as a new cache entry.
#
#   usage: ci-cache-decide.sh <zig-cache dir> <marker touched after restore>
#
# Prints `save=true|false` to $GITHUB_OUTPUT (stdout when unset) and one line
# saying why.
#
# ⭐ WHY THIS EXISTS (2026-09-18). `actions/cache` saves the whole tree under a
# new key whenever its exact key missed, and the key carries a hash of every
# module source -- so every commit re-saved every lane's tree, whether the lane
# compiled anything or not. With stamps most lanes compile nothing on most
# runs, and the copies of trees nothing had added to were what pushed the
# repository past its 10 GB quota (11.19 GB on 2026-09-18) and evicted the
# arm64 lanes' entries. So a tree is saved only when this run added to it.
#
# "Added to" = a new output directory in `o/`. Zig rewrites manifests in `h/`
# on a cache HIT when the checkout gave the sources fresh mtimes, so `h/` moves
# on every run and says nothing; `o/<digest>` appears only when something was
# actually compiled.
#
# A CAP as well: a tree restored and added to run after run grows. Past
# ZIGLIBS_CACHE_CAP_MB (raw, default 4096 -- one lane's single generation measured
# 1.1-3.4 GB) the grown tree is NOT saved and the restored entry stays the base
# (2026-11-14); only when that base is ZIGLIBS_CACHE_RESET_DAYS (7) old is the
# whole tree emptied and saved, so the tree starts over once a week at most.
# ⚠ ALL OF IT, never only the old `o/` (2026-11-02). A manifest in `h/` whose output
# is gone is NOT a miss: Zig's Options step trusts the hit and hands out a path to
# `o/<digest>/options.zig` that does not exist ("unable to load", run 41413426395).
# Manifests are named by the input hash and outputs by the final one, so no file
# name says which manifest belongs to which output, and a manifest this run touched
# on a hit may still point at an old output.
set -uo pipefail

dir="${1:?usage: ci-cache-decide.sh <zig-cache dir> <marker>}"
marker="${2:?usage: ci-cache-decide.sh <zig-cache dir> <marker>}"
cap_mb="${ZIGLIBS_CACHE_CAP_MB:-4096}"
out="${GITHUB_OUTPUT:-/dev/stdout}"

decide() {
    echo "save=$1" >> "$out"
    echo "cache: $2"
}

if [[ ! -d "$dir/o" ]]; then
    decide false "no $dir/o -- nothing was compiled, nothing to save"
    exit 0
fi
if [[ ! -e "$marker" ]]; then
    # No marker means the restore step did not run as expected; saving is the
    # conservative choice, since a missing entry costs a cold lane.
    decide true "no restore marker at $marker -- saving"
    exit 0
fi
new="$(find "$dir/o" -mindepth 1 -maxdepth 1 -newer "$marker" | wc -l)"
size_mb="$(( $(du -sb "$dir" | cut -f1) / 1048576 ))"
# Age of the RESTORED tree: its newest `o/` entry that this run did not create.
# tar keeps mtimes, so this is when the restored entry was last added to.
restored_newest="$(find "$dir/o" -mindepth 1 -maxdepth 1 ! -newer "$marker" -printf '%T@\n' | sort -n | tail -1)"
restored_age_d=0
[[ -n "$restored_newest" ]] && restored_age_d="$(( ($(date +%s) - ${restored_newest%.*}) / 86400 ))"
reset_after_d="${ZIGLIBS_CACHE_RESET_DAYS:-7}"
if (( new == 0 )); then
    decide false "this run compiled nothing new (0 new entries in o/, tree ${size_mb} MB) -- the restored entry stays"
elif (( size_mb > cap_mb )) && (( restored_age_d < reset_after_d )); then
    # ⭐ OVER THE CAP: KEEP THE PREVIOUS ENTRY (2026-11-14). Emptying and saving
    # the empty tree made the NEXT run cold too -- a loop: small (4948 MB),
    # RelFast [rest] (4367 MB) and arm64 [rest] (restored 190 B) all started
    # cold on dispatch 43410103669. The restored entry was under the cap and is
    # still the best base: the next run restores it and compiles only the
    # difference. Partial pruning is not an option (see the header).
    decide false "over the cap (${size_mb} MB > ${cap_mb} MB): not saving -- the restored entry (${restored_age_d} d old) stays the base"
elif (( size_mb > cap_mb )); then
    # The base is too old: its difference to the sources grows every run.
    # Start over once, as before.
    find "$dir" -mindepth 1 -delete
    decide true "over the cap (${size_mb} MB > ${cap_mb} MB) on a base ${restored_age_d} d old (>= ${reset_after_d}): tree emptied, the next run starts over -- saving"
else
    decide true "${new} new entries in o/, tree ${size_mb} MB -- saving"
fi
