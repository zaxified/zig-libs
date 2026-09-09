#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation-testing driver for `diskfree`: copies the module's `src/` into a
scratch directory, applies one textual mutation at a time from `MUTS` below,
and reports whether `zig test` over the mutated `root.zig` still passes
(GREEN = the test suite did NOT notice the mutation — a finding).

Needs a Python interpreter (a foreign toolchain relative to this all-Zig
collection), so per `CONVENTIONS.md` §9 it lives in `modules/diskfree/tools/`
rather than `src/`, and is not wired into any `zig build` step — a manual
instrument, run by hand:

    python3 modules/diskfree/tools/mutate.py

Per this A1 fixer campaign's brief (§3b), moved here 2026-09-10 (A1 fixer
campaign, `diskfree`) from
`20260901-zig-libs-audit/evidence/diskfree-oracle/`, where the 2026-09-03
audit that built it had left it. Only the hardcoded paths changed (this repo
checkout's own absolute path is not something a committed file may carry —
both are now derived from this script's own location and a fresh temp
directory instead).
"""
import os
import shutil
import subprocess
import sys
import tempfile

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(TOOLS_DIR)  # modules/diskfree

MUTS = [
    ("M1  unescapeOctal bounds i+3<len -> i+3<=len (OOB read)", "mounts.zig",
     "raw[i] == '\\\\' and i + 3 < raw.len and", "raw[i] == '\\\\' and i + 3 <= raw.len and"),
    ("M2  isOctalDigit accepts 8 and 9", "mounts.zig",
     "return c >= '0' and c <= '7';", "return c >= '0' and c <= '9';"),
    ("M3  parseMounts drops the empty-line skip", "mounts.zig",
     "        if (line.len == 0) continue;\n        var cols", "        var cols"),
    ("M4  parseMounts accepts a 3-column line (options optional)", "mounts.zig",
     "const options_raw = cols.next() orelse continue;", "const options_raw = cols.next() orelse \"\";"),
    ("M5  parseMounts accepts a 1-column line (all after device optional)", "mounts.zig",
     "        const mount_point_raw = cols.next() orelse continue;\n        const fs_type_raw = cols.next() orelse continue;\n        const options_raw = cols.next() orelse continue;",
     "        const mount_point_raw = cols.next() orelse \"\";\n        const fs_type_raw = cols.next() orelse \"\";\n        const options_raw = cols.next() orelse \"\";"),
    ("M6  parseMounts stops unescaping the device column", "mounts.zig",
     "const device = unescapeOctal(gpa, device_raw) catch continue;", "const device = gpa.dupe(u8, device_raw) catch continue;"),
    ("M7  readVirtualFile: StreamTooLong -> null again (mounts)", "mounts.zig",
     "        error.StreamTooLong => {},", "        error.StreamTooLong => { list.deinit(gpa); return null; },"),
    ("M8  readVirtualFile: StreamTooLong -> null again (mountinfo)", "mountinfo.zig",
     "        error.StreamTooLong => {},", "        error.StreamTooLong => { list.deinit(gpa); return null; },"),
    ("M9  mountinfo drops the missing-'-'-separator refusal", "mountinfo.zig",
     "    if (!found_sep) return error.Malformed;", "    if (!found_sep) {}"),
    ("M10 mountinfo stops unescaping mount_source", "mountinfo.zig",
     "const mount_source = try mounts.unescapeOctal(gpa, mount_source_raw);", "const mount_source = try gpa.dupe(u8, mount_source_raw);"),
    ("M11 mountinfo stops unescaping root", "mountinfo.zig",
     "const root = try mounts.unescapeOctal(gpa, root_raw);", "const root = try gpa.dupe(u8, root_raw);"),
    ("M12 mountinfo: optional_fields always empty", "mountinfo.zig",
     "const optional_fields_raw = if (opt_start) |s| line[s..opt_end] else \"\";", "const optional_fields_raw = \"\";"),
    ("M13 statfs drops the embedded-NUL refusal", "statfs.zig",
     "    if (std.mem.findScalar(u8, path, 0) != null) return error.InvalidPath;", "    if (false) return error.InvalidPath;"),
    ("M14 statfs blockSizeU64 drops the negative clamp", "statfs.zig",
     "return if (u.block_size > 0) @intCast(u.block_size) else 0;", "return @bitCast(u.block_size);"),
    ("M15 statfs totalBytes wraps instead of saturating", "statfs.zig",
     "return u.blocks_total *| blockSizeU64(u);", "return u.blocks_total *% blockSizeU64(u);"),
    ("M16 statfs Native64 reads bfree where bavail belongs", "statfs.zig",
     "        Native64 => .{\n            .block_size = raw.bsize,\n            .fragment_size = raw.frsize,\n            .blocks_total = raw.blocks,\n            .blocks_free = raw.bfree,\n            .blocks_available = raw.bavail,",
     "        Native64 => .{\n            .block_size = raw.bsize,\n            .fragment_size = raw.frsize,\n            .blocks_total = raw.blocks,\n            .blocks_free = raw.bfree,\n            .blocks_available = raw.bfree,"),
    ("M17 statfs Native64 reads frsize where bsize belongs", "statfs.zig",
     "        Native64 => .{\n            .block_size = raw.bsize,", "        Native64 => .{\n            .block_size = raw.frsize,"),
    ("M18 statfs Native64 namelen <- flags", "statfs.zig",
     "            .fs_type_magic = @truncate(@as(u64, @bitCast(raw.type))),\n            .name_max = raw.namelen,",
     "            .fs_type_magic = @truncate(@as(u64, @bitCast(raw.type))),\n            .name_max = raw.flags,"),
    ("M19 statfs family: x86 -> natural32 (88 B, native-i386 reading)", "statfs.zig",
     "    .x86 => .packed32,", "    .x86 => .natural32,"),
    ("M20 statfs Native64 size assert 120 -> 121", "statfs.zig",
     "std.debug.assert(@sizeOf(Native64) == 120);", "std.debug.assert(@sizeOf(Native64) == 121);"),
    ("M21 statfs PackedGeneric32 loses its align(4) packing", "statfs.zig",
     "    blocks: u64 align(4),\n    bfree: u64 align(4),\n    bavail: u64 align(4),\n    files: u64 align(4),\n    ffree: u64 align(4),",
     "    blocks: u64 align(8),\n    bfree: u64 align(8),\n    bavail: u64 align(8),\n    files: u64 align(8),\n    ffree: u64 align(8),"),
    ("M22 mounts unescapeOctal: never decode at all", "mounts.zig",
     "        if (raw[i] == '\\\\' and i + 3 < raw.len and", "        if (false and raw[i] == '\\\\' and i + 3 < raw.len and"),
]


def main() -> int:
    zig = os.environ.get("ZIG", "zig")
    work = tempfile.mkdtemp(prefix="diskfree-mutate-")
    try:
        results = []
        for name, fname, old, new in MUTS:
            mod_dir = os.path.join(work, "mod")
            shutil.rmtree(mod_dir, ignore_errors=True)
            shutil.copytree(SRC, mod_dir)
            p = os.path.join(mod_dir, "src", fname)
            s = open(p).read()
            if old not in s:
                results.append((name, "NOT-APPLIED"))
                print(f"{name}: NOT-APPLIED", flush=True)
                continue
            open(p, "w").write(s.replace(old, new, 1))
            r = subprocess.run(
                [zig, "test", "-ODebug", "-Mmain=" + os.path.join(mod_dir, "src", "root.zig")],
                capture_output=True, text=True, cwd=work, timeout=600,
            )
            tail = (r.stderr or "").strip().split("\n")[-1][:120]
            verdict = "GREEN (suite did NOT notice)" if r.returncode == 0 else "red"
            results.append((name, verdict, tail))
            print(f"{name}: {verdict}   [{tail}]", flush=True)
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
