#!/bin/bash
# SPDX-License-Identifier: MIT
#
# The layout oracle behind `src/stat.zig`'s nine `struct stat` families.
#
# WHY THIS EXISTS. `fstatat`/`fstatat64` takes no size argument, so unlike
# `statfs64` (whose `do_statfs64` returns EINVAL on a size mismatch) the kernel
# performs NO check on the caller's struct layout. Hand it a wrongly-shaped
# buffer and it fills the buffer happily; you then read back silently
# misaligned numbers, forever, on that one architecture. There is no loud
# failure to wait for, which is why the layouts are pinned by an oracle rather
# than by arithmetic done by hand.
#
# WHAT IT DOES. For each architecture, compile a C translation unit that
# includes the REAL kernel UAPI header for that architecture, with a cross
# compiler that knows that architecture's C ABI, and declare one array per
# field sized `offsetof(...) + 1`. The numbers are then read back out of the
# object file's ELF symbol sizes — nothing is executed, so this works for every
# target the toolchain can compile for, not just the host.
#
# WHAT IT CAUGHT that hand arithmetic would not:
#   * s390x puts `st_blocks` at offset 112, where every other 144-byte family
#     puts it at 64 (its blksize/blocks come after the timestamps).
#   * ARM's and i386's `struct stat64` are field-for-field the same C source
#     and different structs — 104 vs 96 bytes, five fields moved — because the
#     i386 SysV ABI aligns an 8-byte scalar to 4 and ARM's EABI to 8.
#
# Every number it prints must match an `assertLayout(...)` call in
# `src/stat.zig`. An architecture this script cannot compile for is NOT
# guessed at: `stat.zig` maps it to `family = .none` (statx-only).
#
# Usage:  bash modules/diskusage/tools/stat-layout-probe.sh [kernel-headers-dir]
# Needs:  zig (as `zig cc`), readelf, and a kernel headers package.

set -u
K=${1:-$(ls -d /usr/src/linux-headers-*/include/uapi/asm-generic/stat.h 2>/dev/null | head -1 | sed 's|/include/uapi/asm-generic/stat.h||')}
if [ -z "${K:-}" ] || [ ! -d "$K" ]; then
  echo "no kernel headers found; pass the directory as \$1 (e.g. /usr/src/linux-headers-6.8.0)" >&2
  exit 2
fi
echo "kernel headers: $K"
TMP=$(mktemp -d) || exit 2
trap 'rm -f "$TMP"/p.c "$TMP"/p.o "$TMP"/err.txt; rmdir "$TMP"' EXIT

probe() { # $1 zig-struct-name  $2 zig-target  $3 kernel-arch-dir|generic  $4 C-struct-name
  local label=$1 tgt=$2 arch=$3 st=$4 inc
  if [ "$arch" = generic ]; then
    inc="-I $K/include/uapi -I $K/include -include $K/include/uapi/asm-generic/stat.h"
  else
    inc="-I $K/include/uapi -I $K/arch/$arch/include/uapi -I $K/include -I $K/arch/$arch/include -include asm/stat.h"
  fi
  cat > "$TMP/p.c" <<EOF
#include <stddef.h>
#define P(n,v) char probe_##n[(v)+1];
P(00_sizeof, sizeof(struct $st))
P(01_dev,    offsetof(struct $st, st_dev))
P(02_ino,    offsetof(struct $st, st_ino))
P(03_mode,   offsetof(struct $st, st_mode))
P(04_nlink,  offsetof(struct $st, st_nlink))
P(05_size,   offsetof(struct $st, st_size))
P(06_blocks, offsetof(struct $st, st_blocks))
EOF
  if ! zig cc -c -target "$tgt" $inc -o "$TMP/p.o" "$TMP/p.c" 2>"$TMP/err.txt"; then
    printf '%-17s %-24s %-8s CANNOT COMPILE: %s\n' "$label" "$tgt" "$st" "$(head -1 "$TMP/err.txt")"
    return
  fi
  # Symbol size is `offsetof + 1` (the +1 keeps a zero offset from producing a
  # zero-size symbol that some linkers drop); subtract it back off here.
  local v
  v=$(readelf -sW "$TMP/p.o" | awk '/probe_/{split($8,a,"probe_"); print a[2]"="$3-1}' | sort | cut -d= -f2 | tr '\n' ' ')
  printf '%-17s %-24s %-8s sizeof=%-4s dev=%-3s ino=%-3s mode=%-3s nlink=%-3s size=%-3s blocks=%s\n' \
    "$label" "$tgt" "$st" $v
}

# 64-bit: `newfstatat`, the architecture's `struct stat`.
probe X8664Stat        x86_64-linux-musl        x86      stat
probe Generic64Stat    aarch64-linux-musl       generic  stat
probe Generic64Stat    riscv64-linux-musl       generic  stat
probe Generic64Stat    loongarch64-linux-musl   generic  stat
probe S390xStat        s390x-linux-musl         s390     stat
probe PowerPc64Stat    powerpc64-linux-musl     powerpc  stat
probe PowerPc64Stat    powerpc64le-linux-musl   powerpc  stat
probe MipsStat         mips64-linux-musl        mips     stat
# 32-bit: `fstatat64`, the architecture's `struct stat64`.
probe MipsStat         mips-linux-musl          mips     stat64
probe MipsStat         mipsel-linux-musl        mips     stat64
probe Generic32Stat64  hexagon-linux-musl       generic  stat64
probe ArmStat64        arm-linux-musleabi       arm      stat64
probe ArmStat64        armeb-linux-musleabi     arm      stat64
probe ArmStat64        thumb-linux-musleabi     arm      stat64
probe X86Stat64        x86-linux-musl           x86      stat64
probe PowerPc32Stat64  powerpc-linux-musl       powerpc  stat64
