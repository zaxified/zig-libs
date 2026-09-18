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
# A CAP as well: a tree restored and added to all week grows until the weekly
# key rolls it over. Past ZIGLIBS_CACHE_CAP_MB (raw, default 4096 -- one lane's
# single generation measured 1.1-3.4 GB) it is not saved, and the lane keeps
# restoring the entry it had.
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
if (( new == 0 )); then
    decide false "this run compiled nothing new (0 new entries in o/, tree ${size_mb} MB) -- the restored entry stays"
elif (( size_mb > cap_mb )); then
    echo "::warning::zig cache tree is ${size_mb} MB, over the ${cap_mb} MB cap -- not saved; the restored entry stays until the weekly key rolls over"
    decide false "over the cap (${size_mb} MB > ${cap_mb} MB, ${new} new entries)"
else
    decide true "${new} new entries in o/, tree ${size_mb} MB -- saving"
fi
