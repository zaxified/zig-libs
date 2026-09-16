#!/usr/bin/env bash
# What is inside every `.zig-cache` under a root, and how much of it is actually
# droppable. Run by hand when looking for disk space. It NEVER deletes anything.
#
#   scripts/cache-usage.sh              # this repository
#   scripts/cache-usage.sh ~/workspace  # every checkout and worktree below a path
#   scripts/cache-usage.sh --all        # ~/workspace plus the usual dev caches
#
# WHY THIS EXISTS. `.zig-cache/` is documented as deletable at any moment, which
# makes it the first place anyone looks when a disk fills up — and that is
# exactly why things that are NOT reproducible keep ending up there. Measured on
# 2026-09-16: of 19.1 GB in this repository's cache, 11.2 GB was forty `audit-*`
# working trees, a GPL reference clone and two oracles, none of which a rebuild
# brings back. A `du -sh` on the directory shows one number and invites deleting
# the lot; this splits the number instead.
#
# ⚠ TWO TRAPS IT EXISTS TO AVOID.
#   1. `du -sh | sort -h` hides the largest entry under a locale with a decimal
#      comma. This measures in bytes (`du -sb`) and sorts numerically.
#   2. Deleting `o/` while keeping `h/` leaves the build runner wedged for good.
#      The suggested command below always names both.
#
# WHAT IT PRODUCES. Per cache: the total, the part the compiler owns and will
# rebuild, and every other top-level entry listed by name and size — those are
# the ones a human has to decide about. Then a grand total of each class.
set -uo pipefail

# Names the Zig toolchain owns inside `.zig-cache`. Everything else is a guest,
# whoever put it there.
COMPILER_OWNED=" o h z tmp p b "

human() { awk -v b="${1:-0}" 'BEGIN{
  split("B KB MB GB TB", u, " "); i=1;
  while (b >= 1024 && i < 5) { b /= 1024; i++ }
  printf (i==1 ? "%d %s" : "%.2f %s"), b, u[i]
}'; }

roots=()
case "${1:-}" in
  --all) roots=("$HOME/workspace" "$HOME/.cache" "$HOME/.cargo" "$HOME/go" "$HOME/.bun") ;;
  "")    roots=("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)") ;;
  -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
  *)     roots=("$1") ;;
esac

total_owned=0 total_guest=0 n_caches=0 n_nested=0
guest_lines=""

# ⚠ NO `-prune` HERE. Pruning at the first `.zig-cache` was this script's own
# first bug: it found 13 of the 27 caches in this repository and hid the rest,
# including a 1.0 GB one inside a tracked module and a 0.67 GB one nested inside
# the cache itself. A cache that hides half the caches is worse than none,
# because it is believed.
#
# The other side of dropping the prune: a cache INSIDE another cache has already
# been counted in its parent's figures, so it is printed (you still want to see
# it) but left out of the totals.
while IFS= read -r cache; do
  [ -d "$cache" ] || continue
  n_caches=$((n_caches + 1))
  nested=0
  case "${cache%/.zig-cache}" in *"/.zig-cache/"*) nested=1; n_nested=$((n_nested + 1)) ;; esac
  owned=0 guest=0 entries=""
  for e in "$cache"/*; do
    [ -e "$e" ] || continue
    name="$(basename "$e")"
    size="$(du -sb "$e" 2>/dev/null | cut -f1)"
    [ -n "$size" ] || continue
    if [[ "$COMPILER_OWNED" == *" $name "* ]]; then
      owned=$((owned + size))
    else
      guest=$((guest + size))
      entries="${entries}${size}\t${name}\n"
    fi
  done
  if [ "$nested" = 1 ]; then
    printf '%s   [nested — already counted in the cache above it]\n' "$cache"
  else
    printf '%s\n' "$cache"
  fi
  printf '    rebuildable (o h z tmp p b): %s\n' "$(human "$owned")"
  printf '    NOT rebuildable:             %s\n' "$(human "$guest")"
  if [ -n "$entries" ]; then
    printf '%b' "$entries" | sort -rn | while IFS=$'\t' read -r s n; do
      [ -n "$n" ] && printf '        %10s  %s\n' "$(human "$s")" "$n"
    done
  fi
  if [ "$nested" = 0 ]; then
    total_owned=$((total_owned + owned))
    total_guest=$((total_guest + guest))
  fi
  [ "$guest" -gt 0 ] && guest_lines="${guest_lines}${guest}\t${cache}\n"
done < <(find "${roots[@]}" -type d -name '.zig-cache' 2>/dev/null | sort)

echo
echo "=== $n_caches cache(s), of which $n_nested nested (not added to the totals) ==="
printf '  rebuildable : %s   — safe to delete, a build brings it back\n' "$(human "$total_owned")"
printf '  guests      : %s   — decide one by one; a rebuild does NOT bring these back\n' "$(human "$total_guest")"
if [ "$n_nested" -gt 0 ]; then
  cat <<'EOF'
  ⚠ the guest figure is an over-estimate by the size of the nested caches above:
    a guest is measured as one blob, so a `.zig-cache` sitting inside one is
    counted there rather than as rebuildable. Read the nested lines for the part
    that a build does bring back.
EOF
fi

if [ "$total_owned" -gt 0 ]; then
  cat <<'EOF'

To reclaim only the rebuildable part, per cache directory C, deleting file by
file (never `rm -rf`, and never `o` without `h`):

    for sub in o h z tmp p b; do
      [ -d "$C/$sub" ] || continue
      find "$C/$sub" -type f -delete
      find "$C/$sub" -depth -type d -empty -delete
    done
EOF
fi

if [ "$total_guest" -gt 0 ]; then
  cat <<'EOF'

The guests are the point of this script. Each is something a person put in a
directory documented as disposable. The fix is not to delete them faster — it is
to move what is worth keeping to where it belongs (an instrument to
`modules/<name>/tools/`, a record to the audit notes) and then drop the rest.
EOF
fi

# ── other build and dependency trees ────────────────────────────────────────
#
# `.zig-cache` is not the only directory that grows quietly. A cargo `target/`,
# a `node_modules/`, a Python venv or a `zig-out/` costs the same disk and is
# just as invisible until something fills up. They are listed here rather than
# analysed, because unlike `.zig-cache` their contents are not ours to classify:
# every one of them is rebuilt by its own toolchain.
#
# ⚠ THIS PASS PRUNES AND THE ONE ABOVE DOES NOT, and the difference is
# deliberate. A `node_modules` inside a `node_modules` is part of its parent and
# counting it twice would inflate the total; a `.zig-cache` inside another one is
# a separate cache that a separate build wrote.
echo
echo "=== other build / dependency trees ==="

# name              marker that proves what it is ("" = the name is enough)
SIGNATURES=(
  "zig-out:"                    # zig install output
  "zig-pkg:"                    # fetched zig packages
  "node_modules:"               # npm / bun / yarn / pnpm
  "target:../Cargo.toml"        # cargo — `target` alone is far too common a word
  "build:CMakeCache.txt"        # cmake — likewise
  ".venv:pyvenv.cfg"            # python venv
  "venv:pyvenv.cfg"
  "__pycache__:"                # python bytecode
  "vendor:../go.mod"            # go vendored deps
  "go-build:"                   # go build cache
  ".gradle:"
  ".m2:"
)

# Collected into a variable rather than piped straight into `sort`, because a
# pipeline runs in a subshell and the running total computed there is lost at
# the far end of it — which would print a list with no sum, the weaker half of
# the answer this script exists to give.
others="$(
  for sig in "${SIGNATURES[@]}"; do
    name="${sig%%:*}"; marker="${sig#*:}"
    while IFS= read -r d; do
      [ -d "$d" ] || continue
      if [ -n "$marker" ]; then
        case "$marker" in
          ../*) [ -e "$(dirname "$d")/${marker#../}" ] || continue ;;
          *)    [ -e "$d/$marker" ] || continue ;;
        esac
      fi
      size="$(du -sb "$d" 2>/dev/null | cut -f1)"
      [ -n "$size" ] || continue
      printf '%s\t%s\n' "$size" "$d"
    done < <(find "${roots[@]}" -type d -name "$name" -prune 2>/dev/null)
  done | sort -rn
)"

if [ -z "$others" ]; then
  echo "  none found"
else
  printf '%s\n' "$others" | head -25 | while IFS=$'\t' read -r s p; do
    [ -n "$p" ] && printf '  %10s  %s\n' "$(human "$s")" "$p"
  done
  n_other="$(printf '%s\n' "$others" | wc -l)"
  other_total="$(printf '%s\n' "$others" | awk -F'\t' '{t+=$1} END{print t+0}')"
  echo
  printf '  %d tree(s), %s total' "$n_other" "$(human "$other_total")"
  [ "$n_other" -gt 25 ] && printf ' (largest 25 shown)'
  printf '\n'
  echo "  each is rebuilt by its own toolchain, so each is droppable — but only"
  echo "  that toolchain's own command puts it back, and some of them need the network"
fi
