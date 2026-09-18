#!/usr/bin/env bash
# ⭐ NO CACHE KEY MAY BE A PREFIX OF ANOTHER, which is a stricter rule than "the
# keys differ" and is not the one .github/workflows/ci.yml was written against.
#
# `actions/cache`'s `restore-keys` matches by PREFIX and returns the newest
# entry that matches. With lane keys `relsafe` and `relsafe-arm64`, the prefix
# `zig-full-relsafe-` matched the ARM64 lane's entry, and on tag 2026-08-15 the
# amd64 ReleaseSafe lane restored an aarch64 object tree: nothing corrupt,
# nothing red, just artifacts built for another architecture. It rebuilt all 225
# modules and compiled for 2540 s, while its sibling lane — same runner image,
# same kernel, same CPU, its own uncontested key — compiled in 91 s.
#
# ci.yml carries a comment telling the next person to check this when they add a
# lane. A comment is not a check, and this bug is invisible without one: both
# lanes stay green either way, and the only symptom is a duration nobody
# compares. So it is checked, in the gate, on every run.
#
# Two invariants, sufficient only together:
#   1. the key template discriminates by architecture, and
#   2. no two DIFFERENT `cachekey` values are prefixes of one another.
#
# Equal values are fine and expected — the two ReleaseSafe lanes share one, and
# (1) is what separates them.
set -uo pipefail

ci="${1:-.github/workflows/ci.yml}"
if [[ ! -f "$ci" ]]; then
    echo "check-ci-cache-keys: no $ci" >&2
    exit 1
fi

template=$(grep -m1 -E '^[[:space:]]*key: zig-full-' "$ci" || true)
if [[ -z "$template" ]]; then
    echo "check-ci-cache-keys: found no 'key: zig-full-…' line in $ci" >&2
    echo "  The key template moved or was renamed. This check cannot vouch for a" >&2
    echo "  file it did not recognise, so it fails rather than passing." >&2
    exit 1
fi

if [[ "$template" != *'runner.arch'* ]]; then
    echo "check-ci-cache-keys: the cache key does not include runner.arch" >&2
    echo "  $template" >&2
    echo "  Without an architecture in the key, two lanes on different" >&2
    echo "  architectures share a restore prefix and one will restore the other's" >&2
    echo "  object tree. See the comment at the top of this file for what it cost." >&2
    exit 1
fi

# ⚠ THE LANES ARE JSON NOW, not `cachekey:` YAML lines — they moved into the
# `plan` job on 2026-08-18 so that `workflow_dispatch` could select one of them
# (a job-level `if:` cannot see the `matrix` context). This check found zero
# keys the moment they moved and failed, which is the behaviour its author
# wanted from it; the pattern is updated here rather than loosened.
keys=()
while IFS= read -r k; do
    [[ -n "$k" ]] && keys+=("$k")
done < <(grep -oE '"cachekey"[[:space:]]*:[[:space:]]*"[^"]+"' "$ci" |
    sed -E 's/.*:[[:space:]]*"([^"]+)"/\1/' || true)

if [[ ${#keys[@]} -lt 2 ]]; then
    echo "check-ci-cache-keys: found ${#keys[@]} cachekey value(s) in $ci; expected at least 2" >&2
    echo "  Either the matrix shrank to one lane or the field was renamed; both" >&2
    echo "  mean this check is no longer looking at what it thinks it is." >&2
    exit 1
fi

rc=0
for a in "${keys[@]}"; do
    for b in "${keys[@]}"; do
        [[ "$a" == "$b" ]] && continue
        if [[ "$b" == "$a"* ]]; then
            echo "check-ci-cache-keys: '$a' is a prefix of '$b'" >&2
            echo "  restore-keys matches by prefix, so the '$a' lane can restore the" >&2
            echo "  '$b' lane's cache. Rename one so neither prefixes the other." >&2
            rc=1
        fi
    done
done
# ⭐ AND THE SCOPED JOB'S SHARDS MUST COVER EVERY PRIMARY LIB (2026-09-18).
# The push lane is a static three-shard matrix (`-Dgroup=`, see ci.yml); a new
# primary lib absent from it would have its modules skipped on every push,
# green. The full lanes get the same check at run time in `plan`, which does
# not run on a push -- so it is made here, where `checks-fast` runs it.
scoped=$(awk '/^  scoped:$/{on=1; next} /^  [a-z_-]+:$/{on=0} on' "$ci")
have=$(grep -oE -- '-Dgroup=[a-z]+' <<< "$scoped" | sed 's/-Dgroup=//' | sort -u | paste -sd' ')
want=$(zig build module-graph 2>/dev/null | cut -f6 | sort -u | paste -sd' ')
if [[ -z "$want" ]]; then
    echo "check-ci-cache-keys: 'zig build module-graph' gave no primary libs -- cannot check the shards" >&2
    rc=1
elif [[ "$have" != "$want" ]]; then
    echo "check-ci-cache-keys: the scoped job's shards cover [$have], module-graph has [$want]" >&2
    echo "  A lib missing here is a set of modules no push ever tests." >&2
    rc=1
fi
exit "$rc"
