// SPDX-License-Identifier: MIT

//! Offline anchor, part two: the reference PARSER's verdicts, replayed.
//!
//! `golden_test.zig` next door replays what the reference's *encoder* produced
//! for the canonical cases. This file replays what its *parser* did with the
//! byte strings a canonical encoder never emits — packing flipped both ways,
//! two copies of a singular submessage, invalid UTF-8 in a `string` field.
//! Those are exactly the rules a round trip through our own codec cannot
//! settle, because our decoder would only ever mirror our own encoder.
//!
//! Until 2026-09-06 they were settled by spawning `python3` from inside
//! `test-protobuf`, which meant the anchor ran only where the reference was
//! installed — never in CI, whose peer install is `continue-on-error`. The
//! live run now lives in `tools/interop.zig`; `--capture` freezes its verdicts
//! into `testdata/interop_vectors.zig`, and this file holds the same ground
//! with no python3 anywhere.
//!
//! The frozen verdict is the reference's own parse, re-serialized canonically
//! (`SerializeToString(deterministic=True)`). So each replay below is: decode
//! the input with OUR decoder, re-encode it canonically, and demand the
//! reference's bytes. A field we read wrongly — or dropped to its default —
//! changes those bytes, which is the same discrimination the live dump
//! comparison had.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");
const conf = @import("conformance.zig");
const vectors = @import("testdata/interop_vectors.zig");
const golden = @import("testdata/golden_bytes.zig");

/// The reference's verdict for `name`, or a compile error if the fixture has
/// none. A semantic case with no frozen verdict would be a case that silently
/// stopped being checked — the exact failure mode this whole split has to
/// avoid, so it is a build failure, not a skip.
fn verdict(comptime name: []const u8) ?[]const u8 {
    inline for (vectors.verdicts) |v| {
        if (comptime std.mem.eql(u8, v.name, name)) return v.normalized;
    }
    @compileError("no frozen verdict for semantic case '" ++ name ++
        "' — run: zig build interop-protobuf -- --capture");
}

/// The reference's encoder output for a named `Wide` case.
fn goldenWide(comptime name: []const u8) []const u8 {
    inline for (golden.wide) |e| {
        if (comptime std.mem.eql(u8, e.name, name)) return e.bytes;
    }
    @compileError("no golden bytes for case '" ++ name ++ "'");
}

fn caseValue(comptime name: []const u8) conf.Wide {
    inline for (conf.wide_cases) |c| {
        if (comptime std.mem.eql(u8, c.name, name)) return c.value;
    }
    @compileError("no `Wide` case named '" ++ name ++ "'");
}

// ── the replay ──────────────────────────────────────────────────────────────

test "interop replay: the reference's reading of every non-canonical input, no python required" {
    const gpa = testing.allocator;
    inline for (conf.semantic_cases) |c| {
        const T = conf.Type(c.msg);
        const frozen = comptime verdict(c.name);
        switch (c.expect) {
            .accept => {
                const want = frozen orelse {
                    std.debug.print("case '{s}' expects acceptance, the fixture records a rejection\n", .{c.name});
                    return error.FixtureContradictsCase;
                };
                var decoded = pb.decode(T, gpa, c.input, .{}) catch |e| {
                    std.debug.print("'{s}': the reference accepted this and we did not ({s})\n", .{ c.name, @errorName(e) });
                    return e;
                };
                defer decoded.deinit();
                const ours = try pb.encodeAlloc(gpa, decoded.value, .{});
                defer gpa.free(ours);
                testing.expectEqualSlices(u8, want, ours) catch |e| {
                    std.debug.print("'{s}': we read different values out of it than the reference did\n", .{c.name});
                    return e;
                };
            },
            .reject_invalid_utf8 => {
                // `null` in the fixture IS the reference's rejection; if a
                // future capture ever records bytes here, this stops the build
                // rather than quietly weakening the case.
                if (frozen != null) {
                    std.debug.print("case '{s}' expects rejection, the fixture records an acceptance\n", .{c.name});
                    return error.FixtureContradictsCase;
                }
                try testing.expectError(error.InvalidUtf8, pb.decode(T, gpa, c.input, .{}));
            },
        }
    }
}

test "interop replay: the flipped-packing input is still what our encoder emits" {
    // The fixture's verdict is about THOSE bytes. If our encoder stops
    // producing them, the frozen verdict no longer describes anything we emit
    // — so this is what keeps the replay honest across an encoder change.
    const gpa = testing.allocator;
    const ours = try pb.encodeAlloc(gpa, conf.Flipped{
        .nums = &.{ 1, 2, 150 },
        .unpacked = &.{ 1, 2, 150 },
    }, .{});
    defer gpa.free(ours);
    try testing.expectEqualSlices(u8, conf.semantic_cases[0].input, ours);

    // …and it really is the non-canonical form: field 1 unpacked where proto3
    // packs, field 2 packed where the schema says it must not be.
    const canonical = try pb.encodeAlloc(gpa, conf.Repeated{
        .nums = &.{ 1, 2, 150 },
        .unpacked = &.{ 1, 2, 150 },
    }, .{});
    defer gpa.free(canonical);
    try testing.expect(!std.mem.eql(u8, ours, canonical));

    // The reference read the same values out of both — the frozen verdict for
    // the flipped bytes IS the canonical encoding.
    try testing.expectEqualSlices(u8, canonical, (comptime verdict("flipped_packing")).?);
}

test "interop replay: two copies of a singular submessage merge, they cannot hide a field" {
    const gpa = testing.allocator;
    const input = conf.semantic_cases[1].input;
    var decoded = try pb.decode(conf.Wide, gpa, input, .{});
    defer decoded.deinit();
    try conf.expectMessageEqual(conf.Wide, .{ .inner = .{ .v = 1, .note = "x" } }, decoded.value);

    // A repeated message field is NOT merged: one element per occurrence.
    var rep = try pb.decode(conf.Repeated, gpa, conf.semantic_cases[2].input, .{});
    defer rep.deinit();
    try testing.expectEqual(@as(usize, 2), rep.value.inners.len);
}

test "interop replay: a message proxied through a partial schema is unchanged" {
    // The old build talking to a new peer. Everything `WidePartial` does not
    // understand has to come back out byte-identical to what the REFERENCE
    // wrote — `golden.wide` is the reference's own encoder output, so this is
    // anchored on the foreign implementation, not on our encoder.
    const gpa = testing.allocator;
    inline for (conf.forwarded_cases) |case| {
        const theirs = comptime goldenWide(case);

        var partial = try pb.decode(conf.WidePartial, gpa, theirs, .{});
        defer partial.deinit();
        try testing.expect(!partial.value.unknown.isEmpty());

        const forwarded = try pb.encodeAlloc(gpa, partial.value, .{});
        defer gpa.free(forwarded);

        var round = pb.decode(conf.Wide, gpa, forwarded, .{}) catch |e| {
            std.debug.print("'{s}': what we forwarded is not parseable\n", .{case});
            return e;
        };
        defer round.deinit();
        conf.expectMessageEqual(conf.Wide, comptime caseValue(case), round.value) catch |e| {
            std.debug.print("unknown fields were not preserved for case '{s}'\n", .{case});
            return e;
        };

        // …and canonically re-encoded, it is the reference's own byte string.
        const canonical = try pb.encodeAlloc(gpa, round.value, .{});
        defer gpa.free(canonical);
        try testing.expectEqualSlices(u8, theirs, canonical);
    }
}

// ── count canary ────────────────────────────────────────────────────────────
//
// `verdict`'s `@compileError` already catches a case with no frozen entry, but
// only for entries this file actually iterates. Pinning the counts also
// catches the other direction — a case deleted from the table while its
// verdict lingers — and a capture run that silently produced fewer entries
// than it meant to.

test "interop replay: vector count canary — 8 semantic cases, 4 of them rejections" {
    try testing.expectEqual(@as(usize, 8), conf.semantic_cases.len);
    try testing.expectEqual(@as(usize, 8), vectors.verdicts.len);

    var rejections: usize = 0;
    for (vectors.verdicts) |v| {
        if (v.normalized == null) rejections += 1;
    }
    try testing.expectEqual(@as(usize, 4), rejections);

    var declared_rejections: usize = 0;
    for (conf.semantic_cases) |c| {
        if (c.expect != .accept) declared_rejections += 1;
    }
    try testing.expectEqual(@as(usize, 4), declared_rejections);
}
