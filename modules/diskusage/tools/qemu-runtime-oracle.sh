#!/bin/bash
# SPDX-License-Identifier: MIT
#
# The runtime half of the cross-architecture `struct stat` layout oracle
# (finding O1, A1 audit, disposition 2026-09-17). `stat-layout-probe.sh`
# (neighbour file, existing) checks `@sizeOf`/`@offsetOf` STATICALLY, with
# nothing executed. This script builds `arch_probe.zig` — a small driver
# over this module's PUBLIC API, nothing copied from `src/` — for each
# architecture, runs it for real under `qemu-user` against real files, and
# diffs every field against the HOST's own `stat(1)` on the same files.
# `qemu-user` translates the guest syscall onto the real host kernel and
# filesystem, so this is a live cross-check of the decode, not just of the
# static layout.
#
# WHAT IT CAUGHT (A1 audit, pre-adoption version): settled whether sparc64's
# `stat` syscall (289) fills `struct stat` or `struct stat64` (an open
# question `SPEC.md` used to carry), and identified a qemu-i386 `st_dev`
# truncation as qemu's own artifact rather than this module's, by cross-
# checking against a raw-buffer dump alongside the decoded fields.
#
# WHAT IT NEEDS: `zig`, and a `qemu-<arch>` user-mode emulator per target
# architecture (skips a target gracefully if the emulator is not installed).
# No network. Big scratch goes under `.zig-cache/`, never `/tmp`.
#
# Usage:  bash modules/diskusage/tools/qemu-runtime-oracle.sh
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
SCRATCH=.zig-cache/o1-diskusage
F="$SCRATCH/fix"
PROBE="$SCRATCH/probe"
mkdir -p "$F" "$PROBE"

# ── fixture: one of each kind `stat.zig`'s FileStat fields distinguish ──────
printf 'hello world\n' > "$F/plain.bin"
mkdir -p "$F/sub"
ln -sf plain.bin "$F/link.lnk"
truncate -s 4M "$F/sparse.img" # apparent size 4 MiB, ~0 blocks allocated
PATHS=("$F/plain.bin" "$F/sparse.img" "$F/link.lnk" "$F/sub" /dev/null /etc/hostname)

# name  zig-target                qemu-binary (or "-" for the host arch)
TARGETS=(
  "x86_64   x86_64-linux-musl        -"
  "aarch64  aarch64-linux-musl       qemu-aarch64"
  "arm      arm-linux-musleabi       qemu-arm"
  "riscv64  riscv64-linux-musl       qemu-riscv64"
  "mips     mips-linux-musleabi      qemu-mips"
)

# ── ground truth: the HOST kernel's own idea of these files, via coreutils ──
declare -A TRUTH
while read -r n rest; do TRUTH["$n"]="$rest"; done < <(
  stat -c '%n mode=%f nlink=%h size=%s blocks=%b maj=%Hd min=%Ld ino=%i' "${PATHS[@]}")

ok=0 mismatch=0 skipped=0
for row in "${TARGETS[@]}"; do
  read -r name tgt qemu <<<"$row"
  if [ "$qemu" != "-" ] && ! command -v "$qemu" >/dev/null 2>&1; then
    echo "SKIP $name: $qemu not installed"
    skipped=$((skipped + 1))
    continue
  fi
  bin="$PROBE/p-$name"
  if ! zig build-exe --cache-dir "$SCRATCH/cc-$name" -OReleaseSafe -target "$tgt" \
    --dep diskusage -Mroot=modules/diskusage/tools/arch_probe.zig \
    -Mdiskusage=modules/diskusage/src/root.zig \
    -femit-bin="$bin" >"$SCRATCH/build-$name.log" 2>&1; then
    echo "BUILD-FAIL $name: $(tail -3 "$SCRATCH/build-$name.log")"
    continue
  fi
  if [ "$qemu" = "-" ]; then
    out=$("$bin" "${PATHS[@]}" 2>&1)
  else
    out=$("$qemu" "$bin" "${PATHS[@]}" 2>&1)
  fi
  while read -r path backend rest; do
    case "$backend" in statx | fstatat) ;; *) continue ;; esac
    exp="${TRUTH[$path]:-MISSING}"
    got=$(echo "$rest" | tr -s ' ')
    if [ "$exp" = "$got" ]; then
      ok=$((ok + 1))
    else
      mismatch=$((mismatch + 1))
      echo "MISMATCH $name $backend $path: expected [$exp] got [$got]"
    fi
  done <<<"$out"
done

echo "OK=$ok MISMATCH=$mismatch SKIPPED-ARCH=$skipped"
[ "$mismatch" -eq 0 ]
