// SPDX-License-Identifier: MIT

//! Shared plumbing for bech32's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay beside their corpora in `bech32.zig`,
//! `base58.zig` and `segwit.zig`; each is generic over its source of
//! choices, `fn(comptime S, *S, gpa)`, and `testing.fuzz` hands it a
//! `std.testing.Smith` (corpus seeds replay as before). This file holds what
//! they share with the driver -- the reach counters, the input draw -- and
//! the encode/decode oracles (a string this module issued is accepted and
//! decodes to what was encoded; a damaged copy is refused).
//!
//! Driver: `BECH32_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_ONLY` selects a harness by name). Harness names: `bech32-decode`,
//! `base58-decode`, `segwit-decode`, `bech32-roundtrip`, `base58-roundtrip`,
//! `segwit-roundtrip`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

const bech32 = @import("bech32.zig");
const base58 = @import("base58.zig");
const segwit = @import("segwit.zig");

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

// ── oracles ──────────────────────────────────────────────────────────────

const RoundMark = enum { genuine_accepted, flipped_refused, bech32m, long };

/// A different char of `alphabet` at `s[at]`.
fn flip(s: []u8, at: usize, alphabet: []const u8) void {
    const i = std.mem.indexOfScalar(u8, alphabet, s[at]).?;
    s[at] = alphabet[(i + 1) % alphabet.len];
}

const BechMark = Marker(RoundMark);

/// encode -> decode returns the same hrp, data and variant; one substituted
/// data-part character is always refused (the BCH code detects up to four
/// errors, BIP173); a truncation is never accepted as the same string.
fn fuzzBech32Roundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var hrp_buf: [bech32.max_hrp_len]u8 = undefined;
    const hrp_len: usize = src.valueRangeAtMost(u8, 1, 12);
    for (hrp_buf[0..hrp_len]) |*c| c.* = src.valueRangeAtMost(u8, 'a', 'z');
    hrp_buf[0] = 'a' + src.valueRangeAtMost(u8, 0, 25);
    // keep a '1' out of the hrp most of the time; a hrp containing '1' is legal too
    if (src.valueRangeAtMost(u8, 0, 7) == 0) hrp_buf[src.index(hrp_len)] = '1';
    const hrp = hrp_buf[0..hrp_len];
    var data: [bech32.max_data_len]u5 = undefined;
    const max_n = bech32.max_len - hrp_len - 1 - bech32.checksum_len;
    const n = if (src.value(bool)) src.index(@min(max_n, 40) + 1) else src.index(max_n + 1);
    for (data[0..n]) |*d| d.* = src.value(u5);
    const enc: bech32.Encoding = if (src.value(bool)) .bech32 else .bech32m;
    if (enc == .bech32m) BechMark.mark(.bech32m);
    if (n > 40) BechMark.mark(.long);

    const s = try bech32.encode(hrp, data[0..n], enc);
    const d = bech32.decode(s.slice()) catch return error.GenuineRefused;
    if (!std.mem.eql(u8, d.hrp(), hrp) or !std.mem.eql(u5, d.data(), data[0..n]) or d.encoding != enc)
        return error.RoundtripMismatch;
    BechMark.mark(.genuine_accepted);

    var copy: [bech32.max_len]u8 = undefined;
    @memcpy(copy[0..s.len], s.slice());
    const sep = std.mem.lastIndexOfScalar(u8, s.slice(), '1').?;
    const at = sep + 1 + src.index(s.len - sep - 1);
    flip(copy[0..s.len], at, bech32.charset);
    if (bech32.decode(copy[0..s.len])) |_| return error.FlippedAccepted else |_| {}
    // Uppercase form is the same string; mixed with a lowercase char is not.
    var upper: [bech32.max_len]u8 = undefined;
    for (s.slice(), 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    const du = bech32.decode(upper[0..s.len]) catch return error.UpperRefused;
    if (!std.mem.eql(u5, du.data(), data[0..n])) return error.UpperMismatch;
    BechMark.mark(.flipped_refused);
}

const B58Mark = Marker(enum { genuine_accepted, flipped_refused, zeros, long });

/// base58 `encode`/`decode` and the Base58Check envelope roundtrip; a
/// substituted alphabet character in a check string is refused.
fn fuzzBase58Roundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var payload: [base58.max_payload_len]u8 = undefined;
    const n = src.index(base58.max_payload_len - base58.checksum_len + 1);
    src.bytes(payload[0..n]);
    const zeros: usize = src.valueRangeAtMost(u8, 0, @intCast(@min(n, 6)));
    @memset(payload[0..zeros], 0);
    if (zeros > 0) B58Mark.mark(.zeros);
    if (n > 40) B58Mark.mark(.long);

    var enc: [base58.max_encoded_len]u8 = undefined;
    var dec: [base58.max_payload_len]u8 = undefined;
    const plain = try base58.encode(payload[0..n], &enc);
    const back = base58.decode(plain, &dec) catch return error.GenuineRefused;
    if (!std.mem.eql(u8, back, payload[0..n])) return error.RoundtripMismatch;

    var enc2: [base58.max_encoded_len]u8 = undefined;
    const chk = base58.checkEncode(payload[0..n], &enc2) catch |e| switch (e) {
        error.PayloadTooLarge => return, // the encoded envelope outgrew the cap
        else => return e,
    };
    const back2 = base58.checkDecode(chk, &dec) catch return error.GenuineRefused;
    if (!std.mem.eql(u8, back2, payload[0..n])) return error.RoundtripMismatch;
    B58Mark.mark(.genuine_accepted);

    var copy: [base58.max_encoded_len]u8 = undefined;
    @memcpy(copy[0..chk.len], chk);
    flip(copy[0..chk.len], src.index(chk.len), base58.alphabet);
    if (base58.checkDecode(copy[0..chk.len], &dec)) |_| return error.FlippedAccepted else |_| {}
    B58Mark.mark(.flipped_refused);
}

const SegMark = Marker(enum { v0, v1plus, genuine_accepted, flipped_refused });

/// encodeSegwit -> decodeSegwit returns the same witness version/program; a
/// substituted data character, or the wrong expected hrp, is refused.
fn fuzzSegwitRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var prog: [segwit.max_program_len]u8 = undefined;
    const witver: u5 = if (src.value(bool)) 0 else src.valueRangeAtMost(u5, 1, 16);
    const n: usize = if (witver == 0)
        (if (src.value(bool)) 20 else 32)
    else
        @as(usize, src.valueRangeAtMost(u8, segwit.min_program_len, segwit.max_program_len));
    src.bytes(prog[0..n]);
    const hrp = if (src.value(bool)) "bc" else "tb";
    if (witver == 0) SegMark.mark(.v0) else SegMark.mark(.v1plus);

    const s = try segwit.encodeSegwit(hrp, witver, prog[0..n]);
    const d = segwit.decodeSegwit(hrp, s.slice()) catch return error.GenuineRefused;
    if (d.witver != witver or !std.mem.eql(u8, d.program(), prog[0..n])) return error.RoundtripMismatch;
    SegMark.mark(.genuine_accepted);

    if (segwit.decodeSegwit(if (hrp[0] == 'b') "tb" else "bc", s.slice())) |_| return error.WrongHrpAccepted else |_| {}
    var copy: [bech32.max_len]u8 = undefined;
    @memcpy(copy[0..s.len], s.slice());
    const sep = std.mem.lastIndexOfScalar(u8, s.slice(), '1').?;
    flip(copy[0..s.len], sep + 1 + src.index(s.len - sep - 1), bech32.charset);
    if (segwit.decodeSegwit(hrp, copy[0..s.len])) |_| return error.FlippedAccepted else |_| {}
    SegMark.mark(.flipped_refused);
}

test "fuzz driver: BECH32_FUZZ (bech32 roundtrip)" {
    try fuzz_driver.run(fuzzBech32Roundtrip, .{ .prefix = "BECH32_FUZZ", .name = "bech32-roundtrip" });
}
test "fuzz driver: BECH32_FUZZ (base58 roundtrip)" {
    try fuzz_driver.run(fuzzBase58Roundtrip, .{ .prefix = "BECH32_FUZZ", .name = "base58-roundtrip" });
}
test "fuzz driver: BECH32_FUZZ (segwit roundtrip)" {
    try fuzz_driver.run(fuzzSegwitRoundtrip, .{ .prefix = "BECH32_FUZZ", .name = "segwit-roundtrip" });
}
test "fuzz harness: roundtrips, 400 seeds, reach every outcome" {
    try BechMark.reach(fuzzBech32Roundtrip, "bech32-roundtrip", 400);
    try B58Mark.reach(fuzzBase58Roundtrip, "base58-roundtrip", 400);
    try SegMark.reach(fuzzSegwitRoundtrip, "segwit-roundtrip", 400);
}

fn bech32RoundtripSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzBech32Roundtrip(testkit.fuzz.ScriptSource, &src, testing.allocator);
}
fn base58RoundtripSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzBase58Roundtrip(testkit.fuzz.ScriptSource, &src, testing.allocator);
}
fn segwitRoundtripSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzSegwitRoundtrip(testkit.fuzz.ScriptSource, &src, testing.allocator);
}
test "fuzz: bech32 roundtrip, exploration" {
    try testing.fuzz({}, bech32RoundtripSmith, .{});
}
test "fuzz: base58 roundtrip, exploration" {
    try testing.fuzz({}, base58RoundtripSmith, .{});
}
test "fuzz: segwit roundtrip, exploration" {
    try testing.fuzz({}, segwitRoundtripSmith, .{});
}
