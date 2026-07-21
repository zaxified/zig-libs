#!/usr/bin/env bash
# Formal weak-memory certification of the lockfree module's synchronization.
# Runs every herd7 litmus test against the shipped AArch64 / RISC-V axiomatic
# models and prints the Observation line for each.
#
# herd7 is installed via opam and is NOT on the default PATH, so we pull it in
# with `opam env`. Requires: opam switch with herdtools7 (herd7 7.58+).
#
# Expected verdicts:
#   *-sc / *-rel-acq  (SAFE, the ordering the code uses)  -> Observation ... Never
#   *-relaxed         (POSITIVE CONTROL, weakened)         -> Observation ... Sometimes
set -u

eval "$(opam env)"

if ! command -v herd7 >/dev/null 2>&1; then
  echo "herd7 not found on PATH after 'opam env' — install herdtools7 in the active opam switch" >&2
  exit 1
fi

cd "$(dirname "$0")" || exit 1

echo "herd7 version: $(herd7 -version)"
echo

fail=0
run() {
  local model="$1" file="$2"
  local obs
  obs="$(herd7 -model "$model" "$file" 2>&1 | grep '^Observation')"
  printf '%-40s %-14s %s\n' "$file" "$model" "${obs:-<no Observation line>}"
  case "$file" in
    *-relaxed.litmus)
      echo "$obs" | grep -q 'Sometimes' || { echo "  !! expected Sometimes (positive control)"; fail=1; } ;;
    *)
      echo "$obs" | grep -q 'Never' || { echo "  !! expected Never (safe variant)"; fail=1; } ;;
  esac
}

echo "== EBR pin/scan Dekker interlock (store-buffering) =="
run aarch64.cat ebr-interlock-aarch64-sc.litmus
run aarch64.cat ebr-interlock-aarch64-relaxed.litmus
run riscv.cat   ebr-interlock-riscv-sc.litmus
run riscv.cat   ebr-interlock-riscv-relaxed.litmus
echo
echo "== Michael-Scott queue publish/consume (message-passing) =="
run aarch64.cat msqueue-aarch64-rel-acq.litmus
run aarch64.cat msqueue-aarch64-relaxed.litmus
run riscv.cat   msqueue-riscv-rel-acq.litmus
run riscv.cat   msqueue-riscv-relaxed.litmus
echo

if [ "$fail" -eq 0 ]; then
  echo "ALL VERDICTS AS EXPECTED: safe variants forbid the bug, positive controls permit it."
else
  echo "MISMATCH: at least one test did not match its expected verdict (see !! above)."
fi
exit "$fail"
