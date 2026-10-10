// SPDX-License-Identifier: MIT

//! Shared plumbing for linkheader's deterministic fuzz driver (added
//! 2026-10-10).
//!
//! The parse harness body stays in `root.zig` beside its corpus, generic over
//! its source of choices, `fn(comptime S, *S, gpa)`; `testing.fuzz` hands it a
//! `std.testing.Smith` (corpus seeds replay as before). This file holds what
//! it shares with the driver -- reach counters, the input draw -- and two
//! oracles: what `write` issued parses back to the same links, and the
//! RFC 8187 / RFC 3986 helpers (`encodeExtValue` / `decodeExtValue`,
//! `unquote`, `resolve`) round-trip or refuse without a panic.
//!
//! Driver: `LINKHEADER_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_ONLY` selects a harness). Harness names: `linkheader-parse`,
//! `linkheader-roundtrip`, `linkheader-helpers`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const lh = @import("root.zig");

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the bend words after the frame are dropped) with 0-3 octets
/// damaged and maybe truncated: random text almost never passes the checksum.
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

// ── oracles ──────────────────────────────────────────────────────────────

const RoundMark = Marker(enum { one_link, many_links, quoted_escape, title_star, extra, genuine_accepted });

/// Draw `n` octets from `set` into `buf`.
fn fill(src: anytype, buf: []u8, n: usize, set: []const u8) []const u8 {
    for (buf[0..n]) |*c| c.* = set[src.index(set.len)];
    return buf[0..n];
}

const uri_set = "abcxyz019/:?=&%.-_~;,@!$*+()[]#{}'|^`";
const val_set = "abcXYZ 019,;=\"\\\t/:.-_<>()@";
const tok_set = "abcdefghijklmnopqrstuvwxyz0123456789-.";

/// Random valid `Link`s -> `write` -> `parse` yields the same links back
/// (uri verbatim, quoted values equal after `unquote`, title* verbatim).
fn fuzzRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const N = 3;
    var uris: [N][40]u8 = undefined;
    var rels: [N][24]u8 = undefined;
    var titles: [N][40]u8 = undefined;
    var types: [N][24]u8 = undefined;
    var stars: [N][48]u8 = undefined;
    var xvals: [N][24]u8 = undefined;
    var links: [N]lh.Link = undefined;
    var extras: [N][1]lh.Param = undefined;
    const n = src.valueRangeAtMost(u8, 1, N);
    if (n == 1) RoundMark.mark(.one_link) else RoundMark.mark(.many_links);
    for (0..n) |i| {
        links[i] = .{
            .uri = fill(src, &uris[i], src.index(uris[i].len + 1), uri_set),
            .rel = fill(src, &rels[i], 1 + src.index(rels[i].len), tok_set),
        };
        if (src.value(bool)) {
            links[i].title = fill(src, &titles[i], src.index(titles[i].len + 1), val_set);
            if (std.mem.indexOfScalar(u8, links[i].title.?, '\\') != null or std.mem.indexOfScalar(u8, links[i].title.?, '"') != null)
                RoundMark.mark(.quoted_escape);
        }
        if (src.value(bool)) links[i].type = fill(src, &types[i], src.index(types[i].len + 1), val_set);
        if (src.value(bool)) {
            var text: [12]u8 = undefined;
            const t = fill(src, &text, src.index(text.len + 1), "abc XYZ_%;\"");
            links[i].title_star = try lh.encodeExtValue(&stars[i], "en", t);
            RoundMark.mark(.title_star);
        }
        if (src.value(bool)) {
            extras[i][0] = .{ .name = "x-note", .value = fill(src, &xvals[i], src.index(xvals[i].len + 1), val_set) };
            links[i].extra = &extras[i];
            RoundMark.mark(.extra);
        }
    }
    var out: [2048]u8 = undefined;
    const text = try lh.bufPrint(&out, links[0..n]);

    var it = lh.parse(text);
    var scratch: [128]u8 = undefined;
    for (links[0..n]) |want| {
        const got = it.next() orelse return error.GenuineLinkLost;
        if (!std.mem.eql(u8, got.uri, want.uri)) return error.UriMismatch;
        if (!std.mem.eql(u8, try lh.unquote(&scratch, got.rel), want.rel)) return error.RelMismatch;
        if (want.title) |t| {
            const g = got.title orelse return error.TitleLost;
            if (!std.mem.eql(u8, try lh.unquote(&scratch, g), t)) return error.TitleMismatch;
        } else if (got.title != null) return error.TitleInvented;
        if (want.type) |t| {
            const g = got.type orelse return error.TypeLost;
            if (!std.mem.eql(u8, try lh.unquote(&scratch, g), t)) return error.TypeMismatch;
        } else if (got.type != null) return error.TypeInvented;
        if (want.title_star) |t| {
            const g = got.title_star orelse return error.TitleStarLost;
            if (!std.mem.eql(u8, g, t)) return error.TitleStarMismatch;
        } else if (got.title_star != null) return error.TitleStarInvented;
        if (want.extra.len != 0) {
            const p = got.param("x-note") orelse return error.ExtraLost;
            if (!std.mem.eql(u8, try lh.unquote(&scratch, p.value), want.extra[0].value)) return error.ExtraMismatch;
        }
    }
    if (it.next() != null) return error.LinkInvented;
    RoundMark.mark(.genuine_accepted);
}

const HelperMark = Marker(enum { ext_roundtrip, ext_refused, resolved, resolve_refused, unquoted });

const helper_seeds = [_][]const u8{
    testkit.fuzz.seed("UTF-8'en'n%c3%a4chstes%20Kapitel"),
    testkit.fuzz.seed("UTF-8''%e2%82%ac%20rates"),
    testkit.fuzz.seed("iso-8859-1'en'%a3%20rates"),
    testkit.fuzz.seed("UTF-8'en'%ff%fe"),
    testkit.fuzz.seed("http://a/b/c/d;p?q|../g"),
    testkit.fuzz.seed("http://a/b/c/d;p?q|//g"),
    testkit.fuzz.seed("http://a/b/c/d;p?q|?y#s"),
    testkit.fuzz.seed("http://a/b/c/d;p?q|g:h"),
    testkit.fuzz.seed("http://a/b/c/d;p?q|../../../../g"),
};

/// `decodeExtValue`, `unquote` and `resolve` on arbitrary / damaged input
/// never panic; an `encodeExtValue` of valid UTF-8 decodes to the same text.
fn fuzzHelpers(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [160]u8 = undefined;
    const len = drawInput(S, src, &buf, &helper_seeds);
    const in = buf[0..len];
    var out: [512]u8 = undefined;

    if (lh.decodeExtValue(&out, in)) |_| HelperMark.mark(.ext_roundtrip) else |_| HelperMark.mark(.ext_refused);
    _ = lh.unquote(&out, in) catch {};
    HelperMark.mark(.unquoted);
    // `base|ref` split at the first '|' (else a fixed base).
    const bar = std.mem.indexOfScalar(u8, in, '|');
    const base = if (bar) |b| in[0..b] else "http://a/b/c/d;p?q";
    const ref = if (bar) |b| in[b + 1 ..] else in;
    var rout: [1024]u8 = undefined;
    if (lh.resolve(&rout, base, ref)) |_| {
        HelperMark.mark(.resolved);
    } else |_| HelperMark.mark(.resolve_refused);

    // encode -> decode of valid UTF-8 text.
    var text: [24]u8 = undefined;
    const t = fill(src, &text, src.index(text.len + 1), "abc XYZ_%;\"\xc3\xa4\xe2\x82\xac~'*");
    if (std.unicode.utf8ValidateSlice(t)) {
        var enc: [160]u8 = undefined;
        const e = try lh.encodeExtValue(&enc, "en", t);
        var dec: [64]u8 = undefined;
        const d = lh.decodeExtValue(&dec, e) catch return error.GenuineExtValueRefused;
        if (!std.mem.eql(u8, d.text, t)) return error.ExtValueRoundtripMismatch;
    }
}

test "fuzz driver: LINKHEADER_FUZZ (roundtrip)" {
    try fuzz_driver.run(fuzzRoundtrip, .{ .prefix = "LINKHEADER_FUZZ", .name = "linkheader-roundtrip" });
}
test "fuzz driver: LINKHEADER_FUZZ (helpers)" {
    try fuzz_driver.run(fuzzHelpers, .{ .prefix = "LINKHEADER_FUZZ", .name = "linkheader-helpers" });
}
test "fuzz harness: roundtrip + helpers, 500 seeds, reach every outcome" {
    try RoundMark.reach(fuzzRoundtrip, "linkheader-roundtrip", 500);
    try HelperMark.reach(fuzzHelpers, "linkheader-helpers", 500);
}

fn roundtripSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzRoundtrip(std.testing.Smith, smith, testing.allocator);
}
fn helpersSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzHelpers(std.testing.Smith, smith, testing.allocator);
}
test "fuzz: roundtrip, exploration" {
    try testing.fuzz({}, roundtripSmith, .{});
}
test "fuzz: helpers, exploration" {
    try testing.fuzz({}, helpersSmith, .{ .corpus = &helper_seeds });
}
