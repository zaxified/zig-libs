#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Hostile-mount-namespace oracle for `diskfree`: mounts tmpfs onto a handful
# of scratch directories inside an UNPRIVILEGED mount namespace (run this
# under `unshare -Ur -m`, never directly — it needs CAP_SYS_ADMIN in that
# namespace, which `unshare -Ur` grants), then captures the resulting
# `/proc/self/mounts`/`/proc/self/mountinfo` plus a `findmnt --json` cross
# check — real kernel output to anchor `mounts.zig`/`mountinfo.zig`'s parsers
# against, the same real-`/proc` oracle `SPEC.md`'s Anchoring section
# describes (73/73 mounts, both formats, on the capture this produced).
#
# Usage:
#     unshare -Ur -m modules/diskfree/tools/hostile-ns.sh [output-dir]
#
# `output-dir` defaults to a fresh `mktemp -d`; printed on exit either way.
#
# Needs `unshare`/mount privilege (an environment `test-<name>` must not
# require) and is not itself Zig, so per `CONVENTIONS.md` §9 this lives in
# `modules/diskfree/tools/`, not `src/`, and is not wired into any `zig
# build` step. Per this A1 fixer campaign's brief (§3b), moved here
# 2026-09-10 (A1 fixer campaign, `diskfree`) from
# `20260901-zig-libs-audit/evidence/diskfree-oracle/`, where the 2026-09-03
# audit that built it had left it. Only the hardcoded paths changed (this
# repo checkout's own absolute path is not something a committed file may
# carry) — the mount-target directories are now created by this script
# itself instead of assumed to pre-exist.
set -eu

OUT="${1:-$(mktemp -d)}"
mkdir -p "$OUT"
MNT="$(mktemp -d)"
mkdir -p "$MNT/a" "$MNT/b" "$MNT/c" "$MNT/d"

for d in "$MNT"/*; do
  mount -t tmpfs -o size=1M,mode=755 hostile-tmpfs "$d" 2>/dev/null || echo "MOUNTFAIL: $d" >&2
done

cp /proc/self/mountinfo "$OUT/live_mountinfo.txt"
cp /proc/self/mounts "$OUT/live_mounts.txt"
findmnt --json > "$OUT/findmnt.json" 2>/dev/null || echo "findmnt failed" >&2
grep -c . "$OUT/live_mountinfo.txt"
grep -n 'hostile-tmpfs' "$OUT/live_mounts.txt" | cat -A | head -20

echo "output: $OUT" >&2
echo "mount targets: $MNT" >&2
