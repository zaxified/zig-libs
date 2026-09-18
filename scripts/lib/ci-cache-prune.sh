#!/usr/bin/env bash
# Delete the GitHub Actions cache entries that a newer entry has superseded.
#
#   usage: ci-cache-prune.sh [--dry-run]      (needs GH_TOKEN with actions: write)
#
# ⭐ WHY (2026-09-18). Every build-cache key carries a hash of the module
# sources (and the push lane's and setup-zig's carry the run), so each run that
# saves adds a new entry and the one it restored from stays behind, still
# counting against the repository's 10 GB. GitHub evicts by LEAST RECENTLY
# USED, and the full matrix runs only on dispatches and tags: between two of
# them, a few pushes' superseded entries were enough to push the full lanes'
# CURRENT entries out -- on 2026-09-18 all three arm64 module lanes restored
# nothing, at 11.19 GB of 10.
#
# An entry's FAMILY is its key minus the parts that change from run to run: the
# ISO week (`-2026W38`), a trailing 64-hex source hash, and setup-zig's
# trailing `-<run id>-<attempt>`. Per family and ref, only the newest entry is
# kept; that is the one every `restore-keys` prefix would pick anyway, so
# nothing reachable is lost. A cache is a cache: at worst a lane runs cold.
set -uo pipefail

dry=0
[[ "${1:-}" == "--dry-run" ]] && dry=1

if ! list="$(gh cache list --limit 1000 --json id,key,ref,createdAt,sizeInBytes \
    --jq '.[] | [.id, .ref, .createdAt, .sizeInBytes, .key] | @tsv')"; then
    echo "::warning::ci-cache-prune: could not list the caches -- nothing pruned"
    exit 0
fi

# family<TAB>id<TAB>ref<TAB>created<TAB>size<TAB>key, newest first per family+ref
victims="$(awk -F'\t' -v OFS='\t' '
    {
        fam = $5
        sub(/-[0-9][0-9][0-9][0-9]W[0-9][0-9]/, "", fam)
        # a trailing 64-hex source hash (no {64}: mawk may lack intervals)
        if (match(fam, /-[0-9a-f]+$/) && RLENGTH == 65) fam = substr(fam, 1, RSTART - 1)
        sub(/-[0-9]+-[0-9]+$/, "", fam)
        print fam, $1, $2, $3, $4, $5
    }' <<< "$list" |
    LC_ALL=C sort -t$'\t' -k1,1 -k3,3 -k4,4r |
    awk -F'\t' -v OFS='\t' '{ k = $1 FS $3; if (seen[k]++) print $2, $5, $6 }')"

if [[ -z "$victims" ]]; then
    echo "ci-cache-prune: nothing superseded ($(wc -l <<< "$list") entries)"
    exit 0
fi

n=0 bytes=0 failed=0
while IFS=$'\t' read -r id size key; do
    if (( dry )); then
        echo "would delete: $key ($(( size / 1048576 )) MB)"
    elif gh cache delete "$id" >/dev/null 2>&1; then
        echo "deleted: $key ($(( size / 1048576 )) MB)"
    else
        # Another run's prune may have got there first; not an error.
        failed=$((failed + 1))
        continue
    fi
    n=$((n + 1))
    bytes=$((bytes + size))
done <<< "$victims"
note=""
(( dry )) && note=" (dry run)"
(( failed )) && note="$note, $failed already gone"
echo "ci-cache-prune: $n superseded entries, $(( bytes / 1048576 )) MB$note"
