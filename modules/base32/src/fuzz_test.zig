// SPDX-License-Identifier: MIT

//! Shared plumbing for base32's deterministic fuzz driver (added 2026-10-10).
//!
//! The decode harness body stays in `root.zig` beside its corpus, generic
//! over its source of choices, `fn(comptime S, *S, gpa)`; `testing.fuzz` hands
//! it a `std.testing.Smith` (corpus seeds replay as before). This file holds
//! what it shares with the driver -- reach counters, the input draw -- and the
//! roundtrip oracle: what `encode` issued is accepted and decodes to the
//! original octets, a substituted symbol never decodes to them.
//!
//! Driver: `BASE32_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness). Harness names: `base32-decode`, `base32-roundtrip`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const b32 = @import("root.zig");

/// Whether this input gets its octets bent into the alphabet. `Smith` always
/// does (the corpus seeds carry bend words); the driver's `Rng` does so for one
/// input in four, because bending every draw destroys the checksum of every
/// corpus-derived input and nothing genuine would ever reach the acceptors.
pub fn bendInput(comptime S: type, src: *S) bool {
    if (S != fuzz_driver.Rng) return true;
    return src.valueRangeAtMost(u8, 0, 3) == 0;
}

/// `Smith.boolWeighted(t, f)` for either source (`Rng` has no such method).
pub fn weighted(src: anytype, comptime t: u32, comptime f: u32) bool {
    if (@TypeOf(src.*) != fuzz_driver.Rng) return src.boolWeighted(t, f);
    return src.r.intRangeLessThan(u32, 0, t + f) < t;
}

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

// ── oracle ───────────────────────────────────────────────────────────────

const Mark = Marker(enum { genuine_accepted, flipped_differs, padded, unpadded, hex, lower });

/// encode (any alphabet / padding / case) -> decode with matching options
/// returns the original octets; strict padding is enforced; one substituted
/// symbol never decodes to the original.
fn fuzzRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var raw: [96]u8 = undefined;
    const n: usize = if (src.value(bool)) src.index(12) else src.index(raw.len + 1);
    src.bytes(raw[0..n]);
    const eo: b32.EncodeOptions = .{
        .alphabet = if (src.value(bool)) .std else .hex,
        .pad = src.value(bool),
        .lowercase = src.value(bool),
    };
    if (eo.alphabet == .hex) Mark.mark(.hex);
    if (eo.lowercase) Mark.mark(.lower);
    if (eo.pad) Mark.mark(.padded) else Mark.mark(.unpadded);
    var enc: [b32.encodedLen(96, true)]u8 = undefined;
    const text = try b32.encode(&enc, raw[0..n], eo);
    const dopts: b32.DecodeOptions = .{
        .alphabet = eo.alphabet,
        .padding = if (eo.pad) .required else .forbidden,
        .case = .insensitive,
    };
    var out: [96]u8 = undefined;
    const m = b32.decode(&out, text, dopts) catch return error.GenuineRefused;
    if (!std.mem.eql(u8, out[0..m], raw[0..n])) return error.RoundtripMismatch;
    Mark.mark(.genuine_accepted);

    // The padding rule is strict in both directions.
    const wrong: b32.DecodeOptions = .{
        .alphabet = eo.alphabet,
        .padding = if (eo.pad) .forbidden else .required,
        .case = .insensitive,
    };
    if (if (eo.pad) std.mem.indexOfScalar(u8, text, '=') != null else text.len % 8 != 0) {
        if (b32.decode(&out, text, wrong)) |_| return error.WrongPaddingModeAccepted else |_| {}
    }

    // One substituted data symbol.
    var data_len = text.len;
    while (data_len > 0 and text[data_len - 1] == '=') data_len -= 1;
    if (data_len == 0) return;
    var copy: [b32.encodedLen(96, true)]u8 = undefined;
    @memcpy(copy[0..text.len], text);
    const syms: []const u8 = if (eo.alphabet == .std) "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" else "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const at = src.index(data_len);
    const cur = std.mem.indexOfScalar(u8, syms, std.ascii.toUpper(text[at])).?;
    const next = syms[(cur + 1 + src.index(syms.len - 1)) % syms.len];
    copy[at] = if (eo.lowercase) std.ascii.toLower(next) else next;
    if (b32.decode(&out, copy[0..text.len], dopts)) |k| {
        if (std.mem.eql(u8, out[0..k], raw[0..n])) return error.FlippedDecodesToOriginal;
    } else |_| {}
    Mark.mark(.flipped_differs);
}

test "fuzz driver: BASE32_FUZZ (roundtrip)" {
    try fuzz_driver.run(fuzzRoundtrip, .{ .prefix = "BASE32_FUZZ", .name = "base32-roundtrip" });
}

test "fuzz harness: roundtrip, 400 seeds, reaches every outcome" {
    try Mark.reach(fuzzRoundtrip, "base32-roundtrip", 400);
}

fn roundtripSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzRoundtrip(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: roundtrip, exploration" {
    try testing.fuzz({}, roundtripSmith, .{});
}
