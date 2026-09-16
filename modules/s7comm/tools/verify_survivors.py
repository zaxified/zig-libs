#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# A survivor is only a finding if the weakened code is GENUINELY weaker. For
# each mutation `tools/mutate.py` reports GREEN, this compiles a small driver
# against the mutated copy and shows what it actually does -- audit F7's
# `server.zig` row, for instance, reads one octet PAST the registered area and
# hands it back in the reply.
#
# ⚠ Paths come from this file's location; the audit version took five
# positional arguments. Nothing under the repository is modified: the mutated
# copy lives in a per-process scratch tree under .zig-cache/.
"""For each mutation the suite did NOT catch, show what the mutant actually
does — a survivor only matters if the weakened code is genuinely weaker.

    python3 verify_survivors.py <src> <work> <zig> <cache> <capped>
"""
import os
import shutil
import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = str(ROOT / "modules/s7comm/src")
WORK = str(ROOT / f".zig-cache/s7comm-survivors/w-{os.getpid()}")
ZIG = "zig"
CACHE = str(ROOT / ".zig-cache")
CAPPED = str(ROOT / "scripts/capped")

# Small drivers compiled against the mutated copy.
W2_PROBE = r'''
const std = @import("std");
const items = @import("MOD/items.zig");
const vars = @import("MOD/vars.zig");
const server = @import("MOD/server.zig");
pub fn main() !void {
    // 64-octet DB inside a 512-octet canary block; read 4 octets at byte 61,
    // i.e. exactly one octet past the end.
    var storage: [512]u8 = @splat(0xC5);
    @memset(storage[128..192], 0x11);
    storage[192] = 0x7E; // the octet just past the area
    var areas = [_]server.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = storage[128..192] }};
    var r = server.Responder.init(.{}, &areas);
    const list = [_]items.Item{try items.Item.at(.db, 1, 61, 0, .byte, 4)};
    var p: [32]u8 = undefined;
    const params = try vars.encodeRequest(.read_var, &list, &p);
    var f: [128]u8 = undefined;
    const total = 4 + 3 + 10 + params.len;
    f[0] = 3; f[1] = 0; f[2] = @intCast(total >> 8); f[3] = @truncate(total);
    f[4] = 2; f[5] = 0xF0; f[6] = 0x80;
    f[7] = 0x32; f[8] = 1; f[9] = 0; f[10] = 0; f[11] = 0; f[12] = 1;
    f[13] = @intCast(params.len >> 8); f[14] = @truncate(params.len); f[15] = 0; f[16] = 0;
    @memcpy(f[17..][0..params.len], params);
    var out: [256]u8 = undefined;
    const rep = (try r.handle(f[0..total], &out)).?;
    std.debug.print("reply data: {x}\n", .{rep[21..]});
    if (std.mem.indexOfScalar(u8, rep[21..], 0x7E) != null)
        std.debug.print("  >>> the octet PAST the area (0x7E) is in the reply\n", .{})
    else
        std.debug.print("  (no out-of-area octet in the reply)\n", .{});
}
'''

W3_PROBE = r'''
const std = @import("std");
const items = @import("MOD/items.zig");
pub fn main() !void {
    // A data block of exactly 5 octets whose item declares a 2-octet payload:
    // 4 header + 2 = 6 > 5, so the honest guard refuses. The mutant accepts and
    // hands back a payload slice one octet past the block.
    var block: [16]u8 = @splat(0xEE);
    block[0] = 0xFF; block[1] = 0x04; block[2] = 0x00; block[3] = 0x10; block[4] = 0xAA;
    var it = items.DataItemIterator.init(block[0..5], 1);
    if (it.next()) |maybe| {
        if (maybe) |d| std.debug.print("ACCEPTED payload len {d}: {x}  (block was 5 octets)\n", .{ d.payload.len, d.payload })
        else std.debug.print("null\n", .{});
    } else |e| std.debug.print("refused {t}\n", .{e});
}
'''

D4_PROBE = r'''
const std = @import("std");
const value = @import("MOD/s7plus_value.zig");
pub fn main() !void {
    // Is the depth still bounded once skipBody's own guard is gone?
    for ([_]usize{ 31, 32, 100, 5000 }) |levels| {
        var b: [16384]u8 = undefined;
        var p: usize = 0;
        var i: usize = 0;
        while (i < levels) : (i += 1) { b[p] = 0; p += 1; b[p] = @intFromEnum(value.Datatype.variant); p += 1; }
        b[p] = 0; p += 1; b[p] = @intFromEnum(value.Datatype.bool); p += 1; b[p] = 1; p += 1;
        if (value.valueLen(b[0..p])) |n| std.debug.print("  {d:>5} nested variants: OK len {d}\n", .{ levels, n })
        else |e| std.debug.print("  {d:>5} nested variants: {t}\n", .{ levels, e });
    }
}
'''

MUTS = [
    ("W2 server read bound +1", "server.zig",
     "            if (start + want > store.len) {",
     "            if (start + want > store.len + 1) {", W2_PROBE),
    ("W3 data-item bound +1", "items.zig",
     "        if (self.pos + 4 + n > self.bytes.len) return error.BadDataLength;",
     "        if (self.pos + 4 + n > self.bytes.len + 1) return error.BadDataLength;", W3_PROBE),
    ("D4 skipBody depth guard removed", "s7plus_value.zig",
     "    if (depth == 0) return error.DepthExceeded;\n\n    if (flags.isArray()) {",
     "    if (false) return error.DepthExceeded;\n\n    if (flags.isArray()) {", D4_PROBE),
]

for name, fname, old, new, probe in MUTS:
    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    shutil.copytree(SRC, os.path.join(WORK, "MOD"))
    p = os.path.join(WORK, "MOD", fname)
    s = open(p).read()
    assert old in s, f"needle miss {name}"
    open(p, "w").write(s.replace(old, new, 1))
    assert open(p).read() != s, f"edit did not land {name}"
    drv = os.path.join(WORK, "drv.zig")
    open(drv, "w").write(probe)
    print(f"--- {name} ---")
    b = subprocess.run([CAPPED, ZIG, "build-exe", "drv.zig", "-O", "ReleaseSafe",
                        "--cache-dir", CACHE, "-femit-bin=" + os.path.join(WORK, "drv")],
                       cwd=WORK, capture_output=True, text=True, timeout=900)
    if b.returncode != 0:
        print("build failed:", b.stderr[:600])
        continue
    r = subprocess.run([os.path.join(WORK, "drv")], capture_output=True, text=True, timeout=300)
    print((r.stdout + r.stderr).strip()[:1200])
