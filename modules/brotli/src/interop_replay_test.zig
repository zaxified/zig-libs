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
fn frozen(comptime name: []const u8, comptime effort: []const u8) blessed.Blessed {
    // ~150 entries (45 shapes x 4 efforts, the variants) x two name comparisons each,
    // resolved at comptime: the default 1000-branch budget does not cover it.
    @setEvalBranchQuota(200_000);
    inline for (blessed.entries) |e| {
        if (comptime std.mem.eql(u8, e.name, name) and std.mem.eql(u8, e.effort, effort)) return e;
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

test "interop replay: every decoder reproduces the plaintext from libbrotli's raw-dictionary streams" {
    const gpa = testing.allocator;
    inline for (corpus.dict_cases) |c| {
        const dict = try c.dict.build(gpa);
        defer gpa.free(dict);
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        const buf = try gpa.alloc(u8, plain.len + 1);
        defer gpa.free(buf);
        inline for (corpus.dict_qualities) |q| {
            const stream = @embedFile("testdata/ref/" ++ comptime corpus.dictRefFile(c, q));
            errdefer std.debug.print("dict {s} q{d}\n", .{ c.name, q });
            const opts: brotli.Options = .{ .dictionary = dict, .max_output = 1 << 24 };
            const a = try brotli.decompress(gpa, stream, opts);
            defer gpa.free(a);
            try testing.expectEqualSlices(u8, plain, a);
            try testing.expectEqualSlices(u8, plain, try brotli.decompressInto(gpa, buf, stream, opts));
            var r: std.Io.Reader = .fixed(stream);
            var w: std.Io.Writer.Allocating = .init(gpa);
            defer w.deinit();
            _ = try brotli.decompressStream(gpa, &r, &w.writer, opts);
            try testing.expectEqualSlices(u8, plain, w.written());
            // The case needs its dictionary (from q5 on; q2 may not use it):
            // without, the stream is refused or decodes to other bytes.
            if (q >= 5) {
                if (brotli.decompress(gpa, stream, .{ .max_output = 1 << 24 })) |other| {
                    defer gpa.free(other);
                    try testing.expect(!std.mem.eql(u8, plain, other));
                } else |_| {}
            }
        }
    }
}

test "interop replay: the decoders reproduce libbrotli's large-window streams, and refuse them unasked" {
    const gpa = testing.allocator;
    inline for (corpus.large_cases) |c| {
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        inline for (corpus.large_qualities) |q| {
            const stream = @embedFile("testdata/ref/" ++ comptime corpus.largeRefFile(c, q));
            errdefer std.debug.print("large {s} q{d}\n", .{ c.name, q });
            try testing.expectError(error.InvalidWindowBits, brotli.decompress(gpa, stream, .{ .max_output = 1 << 26 }));
            const opts: brotli.Options = .{ .large_window = true, .max_output = 1 << 26 };
            const a = try brotli.decompress(gpa, stream, opts);
            defer gpa.free(a);
            try testing.expectEqualSlices(u8, plain, a);
            var r: std.Io.Reader = .fixed(stream);
            var w: std.Io.Writer.Allocating = .init(gpa);
            defer w.deinit();
            _ = try brotli.decompressStream(gpa, &r, &w.writer, opts);
            try testing.expectEqualSlices(u8, plain, w.written());
        }
    }
}

test "interop replay: the decoders reproduce libbrotli's serialized-dictionary streams" {
    // Made by google/brotli built with BROTLI_EXPERIMENTAL (`interop --
    // --brotli-src`): an LZ77 dictionary, custom words, custom transforms
    // (google's triplet order; the streams use ShiftAll), and two pairs
    // chosen by the literal context.
    const gpa = testing.allocator;
    inline for (corpus.serial_cases) |c| {
        const dict = try corpus.serialize(gpa, c.dict);
        defer gpa.free(dict);
        var sd = try brotli.parseSharedDictionary(gpa, dict);
        defer sd.deinit();
        const plain = try c.input.build(gpa);
        defer gpa.free(plain);
        inline for (corpus.serial_qualities) |q| {
            const stream = @embedFile("testdata/ref/" ++ comptime corpus.serialRefFile(c, q));
            errdefer std.debug.print("serial {s} q{d}\n", .{ c.name, q });
            const opts: brotli.Options = .{ .shared_dictionary = &sd, .max_output = 1 << 24 };
            const a = try brotli.decompress(gpa, stream, opts);
            defer gpa.free(a);
            try testing.expectEqualSlices(u8, plain, a);
            var r: std.Io.Reader = .fixed(stream);
            var w: std.Io.Writer.Allocating = .init(gpa);
            defer w.deinit();
            _ = try brotli.decompressStream(gpa, &r, &w.writer, opts);
            try testing.expectEqualSlices(u8, plain, w.written());
            // Without the dictionary: refused, or other bytes.
            if (brotli.decompress(gpa, stream, .{ .max_output = 1 << 24 })) |other| {
                defer gpa.free(other);
                try testing.expect(!std.mem.eql(u8, plain, other));
            } else |_| {}
        }
    }
}

// ── direction 2: our streams, as the reference blessed them ─────────────────

test "interop replay: the encoder still emits the exact streams google/brotli accepted" {
    const gpa = testing.allocator;
    inline for (corpus.encodings) |enc| inline for (corpus.shapes) |shape| {
        if (comptime !enc.covers(shape.name)) continue;
        const record = comptime frozen(shape.name, enc.tag);

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

        const stream = try corpus.encode(gpa, input, enc);
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
    };
}

test "interop replay: the encoder still emits the raw-dictionary streams libbrotli accepted" {
    const gpa = testing.allocator;
    inline for (corpus.dict_cases) |c| inline for (corpus.dict_efforts) |effort| {
        const record = comptime frozen(c.name, "dict_" ++ effort);
        const input = try c.input.build(gpa);
        defer gpa.free(input);
        try testing.expectEqualStrings(record.input_sha256, &digestOf(input));
        const stream = try corpus.encodeDict(gpa, c, @field(brotli.Effort, effort));
        defer gpa.free(stream);
        testing.expectEqualStrings(record.stream_sha256, &digestOf(stream)) catch |e| {
            std.debug.print("dict {s} ({s}): the encoder's output changed; re-bless: zig build interop-brotli -- --capture\n", .{ c.name, effort });
            return e;
        };
    };
}

test "interop replay: the encoder still emits the large-window streams libbrotli accepted" {
    const gpa = testing.allocator;
    inline for (corpus.large_cases) |c| inline for (corpus.large_efforts) |effort| {
        const record = comptime frozen(c.name, "large_" ++ effort);
        const stream = try corpus.encodeLarge(gpa, c, @field(brotli.Effort, effort));
        defer gpa.free(stream);
        testing.expectEqualStrings(record.stream_sha256, &digestOf(stream)) catch |e| {
            std.debug.print("large {s} ({s}): the encoder's output changed; re-bless: zig build interop-brotli -- --capture\n", .{ c.name, effort });
            return e;
        };
    };
}

// ── count canary ────────────────────────────────────────────────────────────
//
// `frozen`'s `@compileError` catches a shape with no blessed entry, but only
// for shapes this file iterates. Pinning the counts catches the other
// direction — a shape deleted while its blessing lingers — and a capture run
// that silently produced fewer entries than it meant to.

test "interop replay: coverage canary — 51 shapes x 6 efforts + 32 variant + 30 dictionary + 12 large-window streams blessed, 27 reference streams" {
    try testing.expectEqual(@as(usize, 51), corpus.shapes.len);
    try testing.expectEqual(@as(usize, 20), corpus.encodings.len);
    try testing.expectEqual(@as(usize, 51 * 6 + 32 + corpus.dict_cases.len * corpus.dict_efforts.len + corpus.large_cases.len * corpus.large_efforts.len), blessed.entries.len);
    try testing.expectEqual(@as(usize, 27), corpus.ref_streams.len);

    // Every blessed entry is (encoding, shape), in capture order: a renamed
    // shape must not silently pick up a neighbour's blessing, and a variant
    // naming a shape that does not exist covers nothing.
    var i: usize = 0;
    for (corpus.encodings) |enc| {
        var covered: usize = 0;
        for (corpus.shapes) |s| {
            if (!enc.covers(s.name)) continue;
            try testing.expectEqualStrings(s.name, blessed.entries[i].name);
            try testing.expectEqualStrings(enc.tag, blessed.entries[i].effort);
            i += 1;
            covered += 1;
        }
        try testing.expectEqual(if (enc.shapes) |l| l.len else corpus.shapes.len, covered);
    }
    for (corpus.dict_cases) |c| for (corpus.dict_efforts) |effort| {
        try testing.expectEqualStrings(c.name, blessed.entries[i].name);
        try testing.expect(std.mem.startsWith(u8, blessed.entries[i].effort, "dict_"));
        try testing.expectEqualStrings(effort, blessed.entries[i].effort[5..]);
        i += 1;
    };
    for (corpus.large_cases) |c| for (corpus.large_efforts) |effort| {
        try testing.expectEqualStrings(c.name, blessed.entries[i].name);
        try testing.expect(std.mem.startsWith(u8, blessed.entries[i].effort, "large_"));
        try testing.expectEqualStrings(effort, blessed.entries[i].effort[6..]);
        i += 1;
    };
    try testing.expectEqual(blessed.entries.len, i);

    // The multi-meta-block shapes really do straddle the boundary — the point
    // of `mixed_*`/`block_*` is lost if the encoder's block size ever changes
    // without them following it.
    try testing.expectEqual(@as(usize, 1 << 20), corpus.block);
}
