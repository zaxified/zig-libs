// SPDX-License-Identifier: MIT

//! Offline anchor: our own encoder, forced to the same (version, ecc, mode,
//! mask) as `reference.py`'s `segno` cases, must reproduce the module grid
//! segno produced -- checked against bytes segno already produced, captured
//! once into `testdata/golden_matrices.zig` and committed. No python3, no
//! subprocess: these tests run everywhere, including CI, which never has
//! segno installed.
//!
//! Why this exists: the module's other 31 tests are self-consistency --
//! round trips, literal pins against the standard, four fuzz harnesses -- and
//! every one of them is blind to a whole defect class by construction. A
//! round trip decodes with the same `Walk` order and the same
//! (possibly-wrong) block-structure table the encode used, so a bug in
//! either one is invisible to it: decode just undoes whatever encode did,
//! correctly or not. Only an *independently placed* grid can catch that --
//! which is what forcing segno to the identical (version, ecc, mask) and
//! diffing module-for-module gives us.
//!
//! `SPEC.md` used to describe exactly this kind of comparison ("672
//! matrices... byte-identical", "320 matrices... byte-identical") with zero
//! test code behind either number -- see the module's CHANGELOG for the
//! 2026-08-18 entry that corrected the claim. This file, `reference.py` and
//! `testdata/golden_matrices.zig` are what make the claim real.

const std = @import("std");
const testing = std.testing;
const qr = @import("root.zig");
const golden = @import("testdata/golden_matrices.zig");

/// Pack `m`'s modules the same way `reference.py`'s `pack_rows` does:
/// row-major, MSB-first, each row starting a fresh byte -- a description of
/// the module grid, not of `Matrix`'s internal bit layout, so this stays
/// meaningful even if that layout changes.
fn packRows(m: *const qr.Matrix, out: []u8) []u8 {
    var o: usize = 0;
    var y: u16 = 0;
    while (y < m.size) : (y += 1) {
        var b: u8 = 0;
        var n: u8 = 0;
        var x: u16 = 0;
        while (x < m.size) : (x += 1) {
            b = (b << 1) | @as(u8, if (m.isDark(x, y)) 1 else 0);
            n += 1;
            if (n == 8) {
                out[o] = b;
                o += 1;
                b = 0;
                n = 0;
            }
        }
        if (n != 0) {
            out[o] = b << @as(u3, @intCast(8 - n));
            o += 1;
        }
    }
    return out[0..o];
}

test "golden: our encoder reproduces segno's module grid, byte-exact, no python required" {
    // Each row is byte-aligned independently (see `packRows`), which costs
    // up to 7 wasted padding bits per row -- more than a single
    // whole-grid packing would, so the buffer is sized off row count x
    // bytes-per-row rather than `Matrix.bits`' tighter continuous packing.
    var scratch: [((qr.max_size + 7) / 8) * qr.max_size]u8 = undefined;

    for (golden.entries) |e| {
        var m: qr.Matrix = undefined;
        qr.encode(&m, e.content, .{
            .ecc = e.ecc,
            .version = e.version,
            .mode = e.mode,
            .mask = e.mask,
        }) catch |err| {
            std.debug.print("golden case '{s}': encode failed: {t}\n", .{ e.name, err });
            return err;
        };

        try testing.expectEqual(e.size, m.size);

        const ours = packRows(&m, &scratch);
        testing.expectEqualSlices(u8, e.bits, ours) catch |err| {
            std.debug.print("golden byte mismatch on case '{s}' (version {d}, ecc {t}, mask {d})\n", .{ e.name, e.version, e.ecc, e.mask });
            return err;
        };
    }
}

// ── count canary ─────────────────────────────────────────────────────────
//
// Guards against `reference.py`'s CASES and this file silently drifting:
// 10 versions x 4 ECC levels (the "spread" set) + 8 masks (the "masks" set)
// + 3 modes (the "modes" set) = 51. A regeneration run that silently
// produced fewer entries than intended (e.g. an early return in `dump()`)
// would still pass the byte comparison above -- fewer cases is not a byte
// mismatch -- so the count is pinned here explicitly.
test "golden: vector count canary — 51 cases (40 spread + 8 masks + 3 modes)" {
    try testing.expectEqual(@as(usize, 51), golden.entries.len);
}
