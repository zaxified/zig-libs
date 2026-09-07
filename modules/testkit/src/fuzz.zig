// SPDX-License-Identifier: MIT
//! Corpus seeds in the format `std.testing.Smith` actually reads.
//!
//! ## Why this exists rather than a line in each harness
//!
//! A `std.testing.fuzz` corpus entry is not the frame you want the harness to
//! see. `Smith.slice` reads a **little-endian `u32` length first** and only
//! then the bytes, so a raw frame handed to it arrives minus its own first four
//! octets — measured on `netaddr`: the seed `"192.168.1.1"` reached the parser
//! as `"168.1.1"`. Every module that burned down its fuzz targets rediscovered
//! this and wrote the same four-line helper: **33 copies across 12 modules in
//! three shapes** by the time it landed here, and the count was growing by
//! roughly eight per module burned down.
//!
//! ## ⚠ The three hazards this carries so the caller does not
//!
//! **1. The array has to be static.** A `const` local in the helper is not
//! promoted, and the returned slice dangles — with the RIGHT length and garbage
//! behind it, which is the hardest shape to notice. Hence the `struct {}`
//! namespace: a container-level `const` is guaranteed to have a lifetime.
//!
//! **2. A seed longer than the harness's buffer is not a seed.** `Smith.slice`
//! clamps the declared length to what remains and then checks it against
//! `rangeAtMost(0, buf.len)`; a length over `buf.len` fails that check and the
//! draw falls back to the range MINIMUM, which is 0. So a 900-octet
//! certificate handed to a harness with a 200-octet buffer is not a large seed,
//! it is the empty one. Hit three times during the burn-down; in one case
//! (`iec62351/tlsprofile`) no real certificate could pass through at all, which
//! was a finding about the harness rather than about the seed.
//!
//! **3. ⛔ A seed is worthless if the harness discards it.** These functions
//! only pay off in a harness that draws with `smith.slice(&buf)`. In the idiom
//! this repository had almost everywhere —
//!
//!     smith.bytes(&buf);
//!     const len = smith.valueRangeAtMost(u16, 0, buf.len);
//!     decode(buf[0..len]);
//!
//! — the seed IS read and IS sitting in `buf`, and `len` is 0 anyway, because
//! `bytes` consumed `@min(buf.len, in.len)` octets and the ranged draw then
//! found fewer than the eight it needs and returned the range minimum
//! (`std/testing/Smith.zig:445`). Measured directly on 2026-09-07 with an
//! 18-octet seed: `buf[0] == 'G'`, `len == 0`. The harness fetches its input
//! and then throws it away. `./scripts/check-fuzz-reach.py` is the gate for
//! that half; this module is the other half, and neither is sufficient alone.

const std = @import("std");

/// A corpus entry carrying `frame` verbatim.
///
///     const seeds = [_][]const u8{
///         fuzz.seed(&.{ 0x03, 0x00, 0x00, 0x16 }),
///         fuzz.seed("GET / HTTP/1.1\r\n\r\n"),
///     };
///     test "fuzz: the framer never panics" {
///         try std.testing.fuzz({}, fuzzFramer, .{ .corpus = &seeds });
///     }
pub fn seed(comptime frame: []const u8) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, @intCast(frame.len))) ++ frame[0..frame.len].*;
    }.bytes;
}

/// The same, from a hex literal. Protocol frames are quoted from a spec or a
/// capture in hex, and `"6f0016000100a5a5"` beside a comment naming the packet
/// is more reviewable against the standard than an escaped byte string.
///
/// An odd-length or non-hex literal is a COMPILE error at the seed, naming it.
pub fn seedHex(comptime h: []const u8) []const u8 {
    return &struct {
        const frame = blk: {
            if (h.len % 2 != 0) @compileError("odd-length hex seed: " ++ h);
            @setEvalBranchQuota(@max(1000, 40 * h.len));
            var out: [h.len / 2]u8 = undefined;
            _ = std.fmt.hexToBytes(&out, h) catch @compileError("bad hex seed: " ++ h);
            break :blk out;
        };
        const bytes = std.mem.toBytes(@as(u32, @intCast(frame.len))) ++ frame;
    }.bytes;
}

/// The runtime form, for a seed a test builds rather than quotes — a frame that
/// comes out of the module's own encoder, or one assembled from a fixture.
///
/// `out` must hold `4 + frame.len` octets; the returned slice aliases it, so it
/// has to outlive the `fuzz` call (a `var` in the test body, not in a block).
pub fn seedInto(out: []u8, frame: []const u8) []const u8 {
    std.debug.assert(out.len >= 4 + frame.len);
    std.mem.writeInt(u32, out[0..4], @intCast(frame.len), .little);
    @memcpy(out[4..][0..frame.len], frame);
    return out[0 .. 4 + frame.len];
}

// ── the anchor: what Smith reads back ────────────────────────────────────────
//
// These are not round-trips of this file against itself. Each drives the real
// `std.testing.Smith` over the produced seed, which is the only thing that
// makes the format claim above testable — and the only thing that will FAIL
// loudly if a future Zig changes `slice`'s framing, instead of leaving 33
// modules quietly seeding nothing.

test "seed: Smith.slice reads the frame back verbatim" {
    const s = seed("GET / HTTP/1.1\r\n\r\n");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [256]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", buf[0..n]);
}

test "seedHex: the same, from hex" {
    const s = seedHex("6f0016000100a5a5");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [64]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x6f, 0x00, 0x16, 0x00, 0x01, 0x00, 0xa5, 0xa5 },
        buf[0..n],
    );
}

test "seedInto: the runtime form reads back the same" {
    var storage: [32]u8 = undefined;
    const s = seedInto(&storage, "hello");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [16]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
}

test "the empty seed is a seed, and it is distinguishable from no seed" {
    const s = seed("");
    try std.testing.expectEqual(@as(usize, 4), s.len);
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), smith.slice(&buf));
}

test "hazard 2: a seed longer than the buffer collapses to nothing" {
    // Not a curiosity — this silently emptied three harnesses during the
    // burn-down. `slice` checks the length against `rangeAtMost(0, buf.len)`
    // and falls back to the range minimum, which is zero.
    const s = seed("0123456789ABCDEF");
    var smith: std.testing.Smith = .{ .in = s };
    var small: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), smith.slice(&small));

    var big: [64]u8 = undefined;
    var smith2: std.testing.Smith = .{ .in = s };
    try std.testing.expectEqual(@as(u32, 16), smith2.slice(&big));
}

test "hazard 3: the collapsing idiom throws the seed away after reading it" {
    // The measurement that decided the shape of the burn-down, pinned here so
    // it cannot quietly stop being true. The seed reaches `buf` — `buf[0]` is
    // 'G' — and the length drawn right after it is 0, so the code under test
    // is handed an empty slice.
    // ⚠ The input here is the RAW frame, not a `seed()` — the collapsing idiom
    // opens with `bytes`, which has no length header, so a corpus written for
    // it carries no prefix. Handed a `seed()` instead, `buf[0]` is the first
    // octet of the u32 length and the point is the same but muddier; that is
    // how this test was first written and it failed, correctly.
    var smith: std.testing.Smith = .{ .in = "GET / HTTP/1.1\r\n\r\n" };
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    try std.testing.expectEqual(@as(u8, 'G'), buf[0]);
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "a seed survives being handed to a second draw" {
    // `bytes` takes `@min(out.len, in.len)`, NOT the whole input — the claim
    // three modules had written into their harnesses. With a frame longer than
    // the buffer, the octets after it are still there for the next draw, which
    // is why `--fuzz` can reproduce a crash that the ordinary lane cannot.
    var storage: [4 + 24]u8 = undefined;
    const s = seedInto(&storage, "AAAAAAAAAAAAAAAA" ++ &[_]u8{ 42, 0, 0, 0, 0, 0, 0, 0 });
    var smith: std.testing.Smith = .{ .in = s[4..] };
    var buf: [16]u8 = undefined;
    smith.bytes(&buf);
    try std.testing.expectEqual(@as(u16, 42), smith.valueRangeAtMost(u16, 0, 256));
}
