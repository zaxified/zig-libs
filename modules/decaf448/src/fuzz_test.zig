// SPDX-License-Identifier: MIT

//! Shared plumbing for decaf448's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `DECAF448_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `decaf448-decode`, `decaf448-group`, `decaf448-hash`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── harnesses ───────────────────────────────────────────────────────────

const element = @import("element.zig");
const scalar = @import("scalar.zig");
const hash = @import("hash.zig");
const Element = element.Element;
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

const DecodeMark = Marker(enum { genuine_accepted, accepted, refused, canonical, damaged_other_element });
const GroupMark = Marker(enum { distributive, associative, inverse, encode_roundtrip, one_way_map });
const HashMark = Marker(enum { hashed, dst_refused });

fn randScalar(k: *Cursor) scalar.CompressedScalar {
    var wide: [114]u8 = undefined;
    for (&wide) |*x| x.* = k.byte();
    return scalar.fromWide(wide);
}

fn decodeSmith(_: void, s: *testing.Smith) !void {
    return fuzzDecode(testing.Smith, s, testing.allocator);
}
test "fuzz: Element.decode never crashes, and what it accepts re-encodes to the same octets" {
    try testing.fuzz({}, decodeSmith, .{});
}
test "fuzz driver: DECAF448_FUZZ (decode)" {
    try fuzz_driver.run(fuzzDecode, .{ .prefix = "DECAF448_FUZZ", .name = "decaf448-decode", .scale = 2 });
}
test "fuzz harness: decode, 300 seeds, reaches every outcome" {
    try DecodeMark.reach(fuzzDecode, "decaf448-decode", 300);
}

fn fuzzDecode(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: Element.EncodedBytes = undefined;
    var genuine: ?Element.EncodedBytes = null;
    var damaged = false;
    if (S == Rng) {
        var raw: [114]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        if (k.byte() & 1 == 0) {
            const s = randScalar(&k);
            const e = Element.scalarMul(Element.generator, &s);
            const enc = e.encode();
            genuine = enc;
            buf = enc;
            const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
            for (0..hits) |_| buf[k.ranged(0, 55)] = k.byte();
            damaged = !std.mem.eql(u8, &buf, &enc);
            // Non-canonical field encodings need the top octets forced.
            if (k.ranged(0, 15) == 0) {
                @memset(buf[40..56], 0xff);
                damaged = true;
            }
        } else src.bytes(&buf);
    } else src.bytes(&buf);
    const e = Element.decode(buf) catch {
        if (genuine != null and !damaged) return error.GenuineElementRefused;
        DecodeMark.mark(.refused);
        return;
    };
    DecodeMark.mark(.accepted);
    if (genuine != null and !damaged) DecodeMark.mark(.genuine_accepted);
    // Canonical: an accepted element has exactly one spelling.
    if (!std.mem.eql(u8, &e.encode(), &buf)) return error.AcceptedElementNotCanonical;
    DecodeMark.mark(.canonical);
    if (damaged) {
        const g = try Element.decode(genuine.?);
        if (g.equals(e)) return error.DamagedEncodingIsSameElement;
        DecodeMark.mark(.damaged_other_element);
    }
}

fn groupSmith(_: void, s: *testing.Smith) !void {
    return fuzzGroup(testing.Smith, s, testing.allocator);
}
test "fuzz: the group law holds on random scalars" {
    try testing.fuzz({}, groupSmith, .{});
}
test "fuzz driver: DECAF448_FUZZ (group)" {
    try fuzz_driver.run(fuzzGroup, .{ .prefix = "DECAF448_FUZZ", .name = "decaf448-group", .scale = 8 });
}
test "fuzz harness: group, 40 seeds, reaches every outcome" {
    try GroupMark.reach(fuzzGroup, "decaf448-group", 40);
}

fn fuzzGroup(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [400]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    const a = randScalar(&k);
    const b = randScalar(&k);
    const g = Element.generator;
    const ag = Element.scalarMul(g, &a);
    const bg = Element.scalarMul(g, &b);
    // (a+b)G == aG + bG
    const sum = scalar.add(a, b);
    if (!Element.scalarMul(g, &sum).equals(ag.add(bg))) return error.NotDistributive;
    GroupMark.mark(.distributive);
    // (a*b)G == a(bG)
    const prod = scalar.mul(a, b);
    if (!Element.scalarMul(g, &prod).equals(Element.scalarMul(bg, &a))) return error.NotAssociative;
    GroupMark.mark(.associative);
    // P - P == identity, P + (-P) == identity, (a-b)G == aG - bG
    if (!ag.sub(ag).equals(Element.identity) or !ag.add(ag.negate()).equals(Element.identity)) return error.NoInverse;
    const diff = scalar.sub(a, b);
    if (!Element.scalarMul(g, &diff).equals(ag.sub(bg))) return error.NoInverse;
    GroupMark.mark(.inverse);
    // encode/decode of every result, and the map to the group.
    for ([_]Element{ ag, bg, ag.add(bg), Element.identity }) |e| {
        const d = try Element.decode(e.encode());
        if (!d.equals(e)) return error.EncodeRoundTripAltered;
    }
    GroupMark.mark(.encode_roundtrip);
    var wide: [112]u8 = undefined;
    for (&wide) |*x| x.* = k.byte();
    const m = element.oneWayMap(wide);
    if (!(try Element.decode(m.encode())).equals(m)) return error.MappedElementNotEncodable;
    GroupMark.mark(.one_way_map);
}

fn hashSmith(_: void, s: *testing.Smith) !void {
    return fuzzHash(testing.Smith, s, testing.allocator);
}
test "fuzz: hashToElement and hashToScalar never crash; errors only on DST bounds" {
    try testing.fuzz({}, hashSmith, .{});
}
test "fuzz driver: DECAF448_FUZZ (hash)" {
    try fuzz_driver.run(fuzzHash, .{ .prefix = "DECAF448_FUZZ", .name = "decaf448-hash", .scale = 4 });
}
test "fuzz harness: hash, 300 seeds, reaches every outcome" {
    try HashMark.reach(fuzzHash, "decaf448-hash", 300);
}

fn fuzzHash(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf = [_]u8{0} ** 512; // a short input fills only a prefix
    src.bytes(&buf);
    if (S == Rng) {
        // The DST bounds (empty, 256 octets) are 1 in 256 draws away; steer a share there.
        switch (buf[2] & 7) {
            0 => buf[0] = 0,
            1 => {
                buf[0] = 255;
                buf[1] = 255;
            },
            else => {},
        }
        if (buf[0] == 0 and buf[1] >= 128) buf[1] = 0;
    }
    // The first two octets split the rest into DST and message: 0..256 octets
    // of DST, so the empty, accepted and too-long cases all occur.
    const dst_len = @min(@as(usize, buf[0]) + buf[1] / 128, buf.len - 2);
    const dst = buf[2 .. 2 + dst_len];
    const msg = buf[2 + dst_len ..];
    const want_err = dst.len == 0 or dst.len > hash.max_dst_length;
    if (hash.hashToElement(msg, dst)) |p| {
        if (want_err) return error.BadDstAccepted;
        const d = try Element.decode(p.encode());
        if (!d.equals(p)) return error.HashedElementNotCanonical;
        HashMark.mark(.hashed);
    } else |err| {
        if (!want_err) return error.GoodDstRefused;
        if (err != error.DstEmpty and err != error.DstTooLong) return error.WrongError;
        HashMark.mark(.dst_refused);
    }
    if (hash.hashToScalar(msg, dst)) |s| {
        if (want_err) return error.BadDstAccepted;
        try scalar.rejectNonCanonical(s);
    } else |_| if (!want_err) return error.GoodDstRefused;
}
