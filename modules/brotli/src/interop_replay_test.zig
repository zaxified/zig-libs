// SPDX-License-Identifier: MIT

//! The reference implementation's verdicts, replayed — no python3, no child
//! process, no skip path.
//!
//! Until 2026-09-06 this ground was held by `src/reference_interop.zig`, which
//! spawned `python3 -c <embedded driver>` from inside `test-brotli`. It ran
//! only where google/brotli's Python binding happened to be installed, which
//! in CI (peer install `continue-on-error`) means: not there. The live run now
//! lives in `tools/interop.zig`; what it observed is committed under
//! `testdata/`, and this file is where that observation does its work.
//!
//! Two directions, the same two the live test had:
//!
//!   1. THE REFERENCE'S OWN STREAMS, decoded by us. `testdata/ref/*.br` were
//!      produced by `brotli.compress` at a pinned quality and window size, so
//!      they carry encoder features this module does not emit itself —
//!      context modelling, block splitting, distance short codes, three
//!      different window sizes. Our decoder must reproduce the plaintext
//!      exactly. This is a genuine foreign artefact: no re-derivation, no
//!      round trip through our own encoder.
//!
//!   2. OUR STREAMS, as google/brotli blessed them. What the reference judged
//!      there was not committed data but a stream our encoder produced, so the
//!      hermetic form is the digest of the exact bytes it accepted
//!      (`testdata/interop_blessed.zig`) plus the shape that generated the
//!      input. If the encoder changes output for any shape, this goes red
//!      until someone re-runs `zig build interop-brotli -- --capture` against
//!      a real google/brotli. That is the intended workflow: an encoder change
//!      no outside implementation has ever accepted is exactly what the anchor
//!      exists to stop.
//!
//! ⚠ What this file must NOT become: a round trip. `compress` followed by our
//! own `decompress` is checked in `root.zig` and proves nothing about RFC 7932
//! — a shared misreading passes it. Every assertion below is against bytes a
//! foreign implementation produced or accepted.

const std = @import("std");
const testing = std.testing;
const brotli = @import("root.zig");
const corpus = @import("interop_corpus.zig");
const blessed = @import("testdata/interop_blessed.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

fn digestOf(bytes: []const u8) [64]u8 {
    var raw: [32]u8 = undefined;
    Sha256.hash(bytes, &raw, .{});
    return std.fmt.bytesToHex(raw, .lower);
}

/// The frozen record for `name`, or a compile error if there is none. A shape
/// with no blessed entry would be a shape that silently stopped being checked
/// — the exact failure this split has to avoid, so it is a build failure.
fn frozen(comptime name: []const u8) blessed.Blessed {
    // 45 shapes x a name comparison each, resolved at comptime: the default
    // 1000-branch budget does not cover it.
    @setEvalBranchQuota(20_000);
    inline for (blessed.entries) |e| {
        if (comptime std.mem.eql(u8, e.name, name)) return e;
    }
    @compileError("no blessed entry for shape '" ++ name ++
        "' — run: zig build interop-brotli -- --capture");
}

// ── direction 1: the reference's own streams ────────────────────────────────

test "interop replay: our decoder reproduces the plaintext from google/brotli's own streams" {
    const gpa = testing.allocator;
    inline for (corpus.ref_streams) |r| {
        const plain = @embedFile("testdata/" ++ r.input);
        const stream = @embedFile("testdata/ref/" ++ r.file);

        const got = brotli.decompress(gpa, stream, .{ .max_output = 1 << 24 }) catch |e| {
            std.debug.print("{s} (q{d} w{d}): our decoder refused the reference's stream\n", .{ r.file, r.quality, r.lgwin });
            return e;
        };
        defer gpa.free(got);
        testing.expectEqualSlices(u8, plain, got) catch |e| {
            std.debug.print("{s} (q{d} w{d}): we decoded the reference's stream to different bytes\n", .{ r.file, r.quality, r.lgwin });
            return e;
        };
    }
}

// ── direction 2: our streams, as the reference blessed them ─────────────────

test "interop replay: the encoder still emits the exact streams google/brotli accepted" {
    const gpa = testing.allocator;
    inline for (corpus.shapes) |shape| {
        const record = comptime frozen(shape.name);

        const input = try corpus.build(gpa, shape);
        defer gpa.free(input);

        // Which side moved? The input digest tells a corpus generator that
        // drifted apart from an encoder that drifted.
        testing.expectEqual(record.input_len, input.len) catch |e| {
            std.debug.print("shape '{s}': the corpus generator no longer produces the input the reference judged\n", .{shape.name});
            return e;
        };
        testing.expectEqualStrings(record.input_sha256, &digestOf(input)) catch |e| {
            std.debug.print("shape '{s}': the corpus generator no longer produces the input the reference judged\n", .{shape.name});
            return e;
        };

        const stream = try brotli.compress(gpa, input);
        defer gpa.free(stream);
        testing.expectEqual(record.stream_len, stream.len) catch |e| {
            std.debug.print(
                \\shape '{s}': the encoder's output changed, so nothing outside this
                \\repository has accepted what it now emits. Re-bless it:
                \\  zig build interop-brotli -- --capture
                \\
            , .{shape.name});
            return e;
        };
        testing.expectEqualStrings(record.stream_sha256, &digestOf(stream)) catch |e| {
            std.debug.print(
                \\shape '{s}': the encoder's output changed, so nothing outside this
                \\repository has accepted what it now emits. Re-bless it:
                \\  zig build interop-brotli -- --capture
                \\
            , .{shape.name});
            return e;
        };
    }
}

// ── count canary ────────────────────────────────────────────────────────────
//
// `frozen`'s `@compileError` catches a shape with no blessed entry, but only
// for shapes this file iterates. Pinning the counts catches the other
// direction — a shape deleted while its blessing lingers — and a capture run
// that silently produced fewer entries than it meant to.

test "interop replay: coverage canary — 45 blessed shapes, 24 reference streams" {
    try testing.expectEqual(@as(usize, 45), corpus.shapes.len);
    try testing.expectEqual(@as(usize, 45), blessed.entries.len);
    try testing.expectEqual(@as(usize, 24), corpus.ref_streams.len);

    // Every blessed name is a shape name, in order: a renamed shape must not
    // silently pick up a neighbour's blessing.
    for (corpus.shapes, blessed.entries) |s, e| {
        try testing.expectEqualStrings(s.name, e.name);
    }

    // The multi-meta-block shapes really do straddle the boundary — the point
    // of `mixed_*`/`block_*` is lost if the encoder's block size ever changes
    // without them following it.
    try testing.expectEqual(@as(usize, 1 << 20), corpus.block);
}
