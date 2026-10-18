// SPDX-License-Identifier: MIT

//! Shared plumbing for aescbc's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `AESCBC_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `aescbc-cbc`, `aescbc-padding`.

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
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
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
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── harnesses ───────────────────────────────────────────────────────────

const aescbc = @import("root.zig");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;
const Aes192 = @import("aes192").Aes192;

const CbcMark = Marker(enum { aes128, aes192, aes256, roundtrip, wide_vs_reference, stream_split, stream_in_place, malleability, misaligned_refused, short_out_refused });
const PadMark = Marker(enum { genuine_unpadded, valid, invalid, xmlenc_valid, xmlenc_invalid, x923_valid, x923_invalid, iso7816_valid, iso7816_invalid, zero_stripped });

fn cbcSmith(_: void, s: *testing.Smith) !void {
    return fuzzCbc(testing.Smith, s, testing.allocator);
}
test "fuzz: CBC round-trips, and a flipped ciphertext bit has the exact CBC effect" {
    try testing.fuzz({}, cbcSmith, .{});
}
test "fuzz driver: AESCBC_FUZZ (cbc)" {
    try fuzz_driver.run(fuzzCbc, .{ .prefix = "AESCBC_FUZZ", .name = "aescbc-cbc" });
}
test "fuzz harness: cbc, 300 seeds, reaches every outcome" {
    try CbcMark.reach(fuzzCbc, "aescbc-cbc", 300);
}

/// The scalar reference the pipelined decrypt must agree with: one std block
/// decrypt at a time, `P[i] = D(C[i]) ^ C[i-1]`.
fn refDecrypt(comptime Aes: type, key: *const [Aes.key_bits / 8]u8, iv: [16]u8, ct: []const u8, out: []u8) void {
    const ctx = Aes.initDec(key.*);
    var prev = iv;
    var i: usize = 0;
    while (i < ct.len) : (i += 16) {
        var pt: [16]u8 = undefined;
        ctx.decrypt(&pt, ct[i..][0..16]);
        for (out[i..][0..16], pt, prev) |*o, a, b| o.* = a ^ b;
        prev = ct[i..][0..16].*;
    }
}

const max_blocks = 3 * 8 + 5; // past three `decryptWide` groups, plus a tail

fn cbcCase(comptime Aes: type, k: *Cursor) !void {
    var key: [Aes.key_bits / 8]u8 = undefined;
    for (&key) |*x| x.* = k.byte();
    var iv: [16]u8 = undefined;
    for (&iv) |*x| x.* = k.byte();
    const cap = max_blocks * 16;
    var pt: [cap]u8 = undefined;
    // The plaintext comes from a PRNG seeded by the cursor: the cursor holds
    // fewer octets than the longest message.
    var fill = std.Random.DefaultPrng.init(std.mem.readInt(u64, &[8]u8{ k.byte(), k.byte(), k.byte(), k.byte(), k.byte(), k.byte(), k.byte(), k.byte() }, .little));
    fill.random().bytes(&pt);
    const blocks = k.ranged(0, max_blocks);
    const len = blocks * 16;
    var ct: [cap]u8 = undefined;
    const n = try aescbc.encrypt(Aes, &key, iv, pt[0..len], &ct);
    if (n != len) return error.WrongLength;
    var back: [cap]u8 = undefined;
    _ = try aescbc.decrypt(Aes, &key, iv, ct[0..len], &back);
    if (!std.mem.eql(u8, back[0..len], pt[0..len])) return error.RoundTripAltered;
    CbcMark.mark(.roundtrip);
    // A ciphertext we did not produce (a damaged one) against the scalar
    // reference: catches a pipelined decrypt that only inverts its own encrypt.
    var noise = ct;
    for (0..k.ranged(0, 3)) |_| noise[k.ranged(0, cap - 1)] ^= k.byte() | 1;
    var want: [cap]u8 = undefined;
    refDecrypt(Aes, &key, iv, noise[0..len], &want);
    _ = try aescbc.decrypt(Aes, &key, iv, noise[0..len], &back);
    if (!std.mem.eql(u8, back[0..len], want[0..len])) return error.DecryptDiffersFromReference;
    if (blocks >= 8) CbcMark.mark(.wide_vs_reference);

    // The same message through `Encryptor`/`Decryptor` in random block-aligned
    // pieces, half the time in place: the chain carried across `update`s must
    // give exactly the one-shot bytes.
    const in_place = k.byte() & 1 == 1;
    var e = aescbc.Encryptor(Aes).init(&key, iv);
    var d = aescbc.Decryptor(Aes).init(&key, iv);
    var sc: [cap]u8 = pt;
    var sd: [cap]u8 = undefined;
    var at: usize = 0;
    var pieces: usize = 0;
    while (at < len) {
        const step = 16 * k.ranged(0, @intCast((len - at) / 16));
        if (in_place) _ = try e.update(sc[at..][0..step], sc[at..][0..step]) else _ = try e.update(pt[at..][0..step], sc[at..][0..step]);
        at += step;
        pieces += 1;
        if (pieces > 64) { // a run of empty steps: finish in one
            _ = try e.update(if (in_place) sc[at..len] else pt[at..len], sc[at..len]);
            at = len;
        }
    }
    if (!std.mem.eql(u8, sc[0..len], ct[0..len])) return error.StreamEncryptDiffers;
    at = 0;
    pieces = 0;
    if (in_place) @memcpy(sd[0..len], sc[0..len]);
    while (at < len) {
        const step = 16 * k.ranged(0, @intCast((len - at) / 16));
        if (in_place) _ = try d.update(sd[at..][0..step], sd[at..][0..step]) else _ = try d.update(ct[at..][0..step], sd[at..][0..step]);
        at += step;
        pieces += 1;
        if (pieces > 64) {
            if (in_place) _ = try d.update(sd[at..len], sd[at..len]) else _ = try d.update(ct[at..len], sd[at..len]);
            at = len;
        }
    }
    if (!std.mem.eql(u8, sd[0..len], pt[0..len])) return error.StreamDecryptDiffers;
    if (pieces > 1) {
        if (in_place) CbcMark.mark(.stream_in_place) else CbcMark.mark(.stream_split);
    }

    if (blocks > 0) {
        // Flip bit `b` of ciphertext octet `at` in block `bi`: block `bi` of the
        // plaintext changes (to garbage), block `bi+1` changes by exactly that
        // bit at that position, every other block is untouched.
        const bi = k.ranged(0, @intCast(blocks - 1));
        const pos = k.ranged(0, 15);
        const bit = @as(u8, 1) << @intCast(k.ranged(0, 7));
        var bad = ct;
        bad[bi * 16 + pos] ^= bit;
        var out: [cap]u8 = undefined;
        _ = try aescbc.decrypt(Aes, &key, iv, bad[0..len], &out);
        for (0..blocks) |b| {
            const got = out[b * 16 ..][0..16];
            const wb = pt[b * 16 ..][0..16];
            if (b == bi) {
                if (std.mem.eql(u8, got, wb)) return error.FlippedBlockUnchanged;
            } else if (b == bi + 1) {
                var expect: [16]u8 = wb.*;
                expect[pos] ^= bit;
                if (!std.mem.eql(u8, got, &expect)) return error.NextBlockNotXorOfFlip;
            } else if (!std.mem.eql(u8, got, wb)) return error.OtherBlockChanged;
        }
        CbcMark.mark(.malleability);
        var o2: [cap]u8 = undefined;
        if (aescbc.decrypt(Aes, &key, iv, ct[0 .. len - 1], &o2)) |_| return error.MisalignedAccepted else |er| if (er != error.NotBlockAligned) return error.WrongError;
        if (aescbc.encrypt(Aes, &key, iv, pt[0 .. len - 1], &o2)) |_| return error.MisalignedAccepted else |er| if (er != error.NotBlockAligned) return error.WrongError;
        const chain_before = d.chain;
        if (d.update(ct[0 .. len - 1], &o2)) |_| return error.MisalignedAccepted else |er| if (er != error.NotBlockAligned) return error.WrongError;
        if (!std.mem.eql(u8, &d.chain, &chain_before)) return error.ErrorMovedTheChain;
        CbcMark.mark(.misaligned_refused);
        if (aescbc.decrypt(Aes, &key, iv, ct[0..len], o2[0 .. len - 1])) |_| return error.ShortOutAccepted else |er| if (er != error.BufferTooSmall) return error.WrongError;
        if (e.update(pt[0..len], o2[0 .. len - 1])) |_| return error.ShortOutAccepted else |er| if (er != error.BufferTooSmall) return error.WrongError;
        CbcMark.mark(.short_out_refused);
    }
}

fn fuzzCbc(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [256]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    switch (k.byte() % 3) {
        0 => {
            CbcMark.mark(.aes128);
            try cbcCase(Aes128, &k);
        },
        1 => {
            CbcMark.mark(.aes192);
            try cbcCase(Aes192, &k);
        },
        else => {
            CbcMark.mark(.aes256);
            try cbcCase(Aes256, &k);
        },
    }
}

fn padSmith(_: void, s: *testing.Smith) !void {
    return fuzzPad(testing.Smith, s, testing.allocator);
}
test "fuzz: padding agrees with a plain reference" {
    try testing.fuzz({}, padSmith, .{});
}
test "fuzz driver: AESCBC_FUZZ (padding)" {
    try fuzz_driver.run(fuzzPad, .{ .prefix = "AESCBC_FUZZ", .name = "aescbc-padding" });
}
test "fuzz harness: padding, 300 seeds, reaches every outcome" {
    try PadMark.reach(fuzzPad, "aescbc-padding", 300);
}

/// The straightforward, branching reference the constant-time `unpadPkcs7`
/// must agree with on every buffer.
fn refUnpad(buf: []const u8) ?usize {
    if (buf.len == 0 or buf.len % 16 != 0) return null;
    const nn = buf[buf.len - 1];
    if (nn == 0 or nn > 16) return null;
    for (buf[buf.len - nn ..]) |b| if (b != nn) return null;
    return buf.len - nn;
}

/// Branching references for the other unpadders.
fn refUnpadX923(buf: []const u8) ?usize {
    if (buf.len == 0 or buf.len % 16 != 0) return null;
    const nn = buf[buf.len - 1];
    if (nn == 0 or nn > 16) return null;
    for (buf[buf.len - nn .. buf.len - 1]) |b| if (b != 0) return null;
    return buf.len - nn;
}

fn refUnpadIso7816(buf: []const u8) ?usize {
    if (buf.len == 0 or buf.len % 16 != 0) return null;
    var i = buf.len;
    while (i > buf.len - 16) {
        i -= 1;
        if (buf[i] == 0x80) return i;
        if (buf[i] != 0) return null;
    }
    return null;
}

fn refUnpadZero(buf: []const u8) ?usize {
    if (buf.len % 16 != 0) return null;
    var i = buf.len;
    const floor = if (buf.len == 0) 0 else buf.len - 16;
    while (i > floor and buf[i - 1] == 0) i -= 1;
    return i;
}

const Scheme = enum { pkcs7, x923, iso10126, iso7816, zero };

fn fuzzPad(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [80]u8 = undefined;
    var len: usize = undefined;
    var genuine: ?[]const u8 = null;
    var scheme: Scheme = .pkcs7;
    var msg_store: [64]u8 = undefined;
    if (S == Rng) {
        var raw: [96]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        for (&msg_store) |*x| x.* = k.byte();
        const msg = msg_store[0..k.ranged(0, 63)];
        scheme = @fromBackingInt(@intCast(k.ranged(0, 4)));
        var r = std.Random.DefaultPrng.init(k.byte());
        len = switch (scheme) {
            .pkcs7 => try aescbc.padPkcs7(msg, &buf),
            .x923 => try aescbc.padAnsiX923(msg, &buf),
            .iso10126 => try aescbc.padIso10126(msg, &buf, r.random()),
            .iso7816 => try aescbc.padIso7816(msg, &buf),
            .zero => try aescbc.padZero(msg, &buf),
        };
        const want_len = if (scheme == .zero) aescbc.paddedLenZero(msg.len) else aescbc.paddedLen(msg.len);
        if (len != want_len) return error.PaddedLenWrong;
        const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
        if (len > 0) for (0..hits) |_| {
            buf[len - 1 - k.ranged(0, 17) % len] = k.byte();
        };
        if (len > 0 and k.ranged(0, 7) == 0) len -= 1; // unaligned
        if (hits == 0 and len % 16 == 0) genuine = msg;
    } else {
        len = src.slice(&buf);
    }
    const b = buf[0..len];
    const got = aescbc.unpadPkcs7(b);
    const want = refUnpad(b);
    if (want) |w| {
        const g = got catch return error.ValidPaddingRefused;
        if (g != w) return error.UnpaddedLengthDiffers;
        PadMark.mark(.valid);
    } else {
        if (got) |_| return error.InvalidPaddingAccepted else |_| {}
        if (genuine != null and scheme == .pkcs7) return error.GenuinePaddingRefused;
        PadMark.mark(.invalid);
    }
    // XML-Enc / ISO 10126: only the final length octet matters.
    const xml = aescbc.unpadXmlEnc(b);
    const xml_want: ?usize = if (len == 0 or len % 16 != 0 or buf[len - 1] == 0 or buf[len - 1] > 16) null else len - buf[len - 1];
    try agree(xml, xml_want, .xmlenc_valid, .xmlenc_invalid);
    try agree(aescbc.unpadAnsiX923(b), refUnpadX923(b), .x923_valid, .x923_invalid);
    try agree(aescbc.unpadIso7816(b), refUnpadIso7816(b), .iso7816_valid, .iso7816_invalid);
    const z = aescbc.unpadZero(b);
    try agree(z, refUnpadZero(b), .zero_stripped, .zero_stripped);
    if (genuine) |m| {
        const g = switch (scheme) {
            .pkcs7 => try aescbc.unpadPkcs7(b),
            .x923 => try aescbc.unpadAnsiX923(b),
            .iso10126 => try aescbc.unpadIso10126(b),
            .iso7816 => try aescbc.unpadIso7816(b),
            .zero => try aescbc.unpadZero(b),
        };
        // Zero padding loses the message's own trailing zeros, by definition
        // (at most those of its last block).
        const expect = if (scheme == .zero) std.mem.trimEnd(u8, m, "\x00") else m;
        const have = if (scheme == .zero) std.mem.trimEnd(u8, b[0..g], "\x00") else b[0..g];
        if (!std.mem.eql(u8, have, expect)) return error.GenuineMessageAltered;
        PadMark.mark(.genuine_unpadded);
    }
}

fn agree(got: aescbc.PaddingError!usize, want: ?usize, comptime ok: anytype, comptime bad: anytype) !void {
    if (want) |w| {
        if ((got catch return error.ValidPaddingRefused) != w) return error.UnpaddedLengthDiffers;
        PadMark.mark(ok);
    } else {
        if (got) |_| return error.InvalidPaddingAccepted else |_| {}
        PadMark.mark(bad);
    }
}

// ── ciphertext stealing ─────────────────────────────────────────────────

const CtsMark = Marker(enum { cs1, cs2, cs3, one_block, partial_tail, full_tail, too_short });

fn ctsSmith(_: void, s: *testing.Smith) !void {
    return fuzzCts(testing.Smith, s, testing.allocator);
}
test "fuzz: CTS agrees with a zero-padded CBC model, and inverts" {
    try testing.fuzz({}, ctsSmith, .{});
}
test "fuzz driver: AESCBC_FUZZ (cts)" {
    try fuzz_driver.run(fuzzCts, .{ .prefix = "AESCBC_FUZZ", .name = "aescbc-cts" });
}
test "fuzz harness: cts, 300 seeds, reaches every outcome" {
    try CtsMark.reach(fuzzCts, "aescbc-cts", 300);
}

/// The model: plain CBC over the message zero-filled to whole blocks, then
/// C_{n-1} cut to the tail's length d and the last two pieces ordered per
/// variant (SP800-38A Addendum's definition, not its algorithm).
fn ctsModel(comptime Aes: type, variant: aescbc.CtsVariant, key: *const [Aes.key_bits / 8]u8, iv: [16]u8, msg: []const u8, out: []u8) void {
    var padded: [8 * 16]u8 = @splat(0);
    const n = (msg.len + 15) / 16;
    @memcpy(padded[0..msg.len], msg);
    var cbc: [8 * 16]u8 = undefined;
    _ = aescbc.encrypt(Aes, key, iv, padded[0 .. n * 16], &cbc) catch unreachable;
    if (n == 1) {
        @memcpy(out[0..16], cbc[0..16]);
        return;
    }
    const d = msg.len - (n - 1) * 16;
    const head = (n - 2) * 16;
    @memcpy(out[0..head], cbc[0..head]);
    const swap = switch (variant) {
        .cs1 => false,
        .cs2 => d != 16,
        .cs3 => true,
    };
    const prev = cbc[head..][0..d];
    const last = cbc[head + 16 ..][0..16];
    if (swap) {
        @memcpy(out[head..][0..16], last);
        @memcpy(out[head + 16 ..][0..d], prev);
    } else {
        @memcpy(out[head..][0..d], prev);
        @memcpy(out[head + d ..][0..16], last);
    }
}

fn ctsCase(comptime Aes: type, k: *Cursor) !void {
    var key: [Aes.key_bits / 8]u8 = undefined;
    for (&key) |*x| x.* = k.byte();
    var iv: [16]u8 = undefined;
    for (&iv) |*x| x.* = k.byte();
    var msg: [8 * 16]u8 = undefined;
    var fill = std.Random.DefaultPrng.init(k.byte());
    fill.random().bytes(&msg);
    const len = k.ranged(0, 8 * 16);
    const variant: aescbc.CtsVariant = @fromBackingInt(@intCast(k.ranged(0, 2)));
    var got: [8 * 16]u8 = undefined;
    if (len < 16) {
        if (aescbc.encryptCts(Aes, variant, &key, iv, msg[0..len], &got)) |_| return error.ShortAccepted else |e| if (e != error.TooShort) return error.WrongError;
        if (aescbc.decryptCts(Aes, variant, &key, iv, msg[0..len], &got)) |_| return error.ShortAccepted else |e| if (e != error.TooShort) return error.WrongError;
        CtsMark.mark(.too_short);
        return;
    }
    var want: [8 * 16]u8 = undefined;
    ctsModel(Aes, variant, &key, iv, msg[0..len], &want);
    if (try aescbc.encryptCts(Aes, variant, &key, iv, msg[0..len], &got) != len) return error.WrongLength;
    if (!std.mem.eql(u8, got[0..len], want[0..len])) return error.CtsDiffersFromModel;
    // Back, half the time in place.
    var back: [8 * 16]u8 = undefined;
    if (k.byte() & 1 == 0) {
        _ = try aescbc.decryptCts(Aes, variant, &key, iv, got[0..len], &back);
    } else {
        back = got;
        _ = try aescbc.decryptCts(Aes, variant, &key, iv, back[0..len], back[0..len]);
    }
    if (!std.mem.eql(u8, back[0..len], msg[0..len])) return error.CtsRoundTripAltered;
    switch (variant) {
        .cs1 => CtsMark.mark(.cs1),
        .cs2 => CtsMark.mark(.cs2),
        .cs3 => CtsMark.mark(.cs3),
    }
    if (len == 16) CtsMark.mark(.one_block) else if (len % 16 == 0) CtsMark.mark(.full_tail) else CtsMark.mark(.partial_tail);
}

fn fuzzCts(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [128]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    switch (k.byte() % 3) {
        0 => try ctsCase(Aes128, &k),
        1 => try ctsCase(Aes192, &k),
        else => try ctsCase(Aes256, &k),
    }
}

// ── streaming with padding ──────────────────────────────────────────────

const StreamMark = Marker(enum { none, pkcs7, ansi_x923, iso7816, zero, split, unaligned_refused, bad_padding_refused });

fn streamSmith(_: void, s: *testing.Smith) !void {
    return fuzzStream(testing.Smith, s, testing.allocator);
}
test "fuzz: streaming in random pieces equals pad + one-shot, both ways" {
    try testing.fuzz({}, streamSmith, .{});
}
test "fuzz driver: AESCBC_FUZZ (stream)" {
    try fuzz_driver.run(fuzzStream, .{ .prefix = "AESCBC_FUZZ", .name = "aescbc-stream" });
}
test "fuzz harness: stream, 300 seeds, reaches every outcome" {
    try StreamMark.reach(fuzzStream, "aescbc-stream", 300);
}

fn streamCase(comptime padding: aescbc.Padding, k: *Cursor) !void {
    const Aes = Aes128;
    var key: [16]u8 = undefined;
    for (&key) |*x| x.* = k.byte();
    var iv: [16]u8 = undefined;
    for (&iv) |*x| x.* = k.byte();
    var msg: [100]u8 = undefined;
    var fill = std.Random.DefaultPrng.init(k.byte());
    fill.random().bytes(&msg);
    const len = if (padding == .none) 16 * k.ranged(0, 6) else k.ranged(0, 100);
    // The model: pad the whole message, encrypt it in one call.
    var padded: [128]u8 = undefined;
    const plen = switch (padding) {
        .none => blk: {
            @memcpy(padded[0..len], msg[0..len]);
            break :blk len;
        },
        .pkcs7 => try aescbc.padPkcs7(msg[0..len], &padded),
        .ansi_x923 => try aescbc.padAnsiX923(msg[0..len], &padded),
        .iso7816 => try aescbc.padIso7816(msg[0..len], &padded),
        .zero => try aescbc.padZero(msg[0..len], &padded),
    };
    var want: [128]u8 = undefined;
    _ = try aescbc.encrypt(Aes, &key, iv, padded[0..plen], &want);

    var e = aescbc.StreamEncryptor(Aes, padding).init(&key, iv);
    var got: [128 + 16]u8 = undefined;
    var w: usize = 0;
    var at: usize = 0;
    var pieces: usize = 0;
    while (at < len and pieces < 40) : (pieces += 1) {
        const step = k.ranged(0, @intCast(len - at));
        const room = e.maxUpdateLen(step);
        w += try e.update(msg[at..][0..step], got[w..][0..room]);
        at += step;
    }
    w += try e.update(msg[at..len], got[w..]);
    w += try e.finish(got[w..]);
    if (w != plen or !std.mem.eql(u8, got[0..w], want[0..plen])) return error.StreamEncryptDiffers;

    var d = aescbc.StreamDecryptor(Aes, padding).init(&key, iv);
    var back: [128 + 16]u8 = undefined;
    var r: usize = 0;
    at = 0;
    pieces = 0;
    while (at < plen and pieces < 40) : (pieces += 1) {
        const step = k.ranged(0, @intCast(plen - at));
        r += try d.update(want[at..][0..step], back[r..][0..d.maxUpdateLen(step)]);
        at += step;
    }
    r += try d.update(want[at..plen], back[r..]);
    r += try d.finish(back[r..]);
    const expect = if (padding == .zero) std.mem.trimEnd(u8, msg[0..len], "\x00") else msg[0..len];
    const have = if (padding == .zero) std.mem.trimEnd(u8, back[0..r], "\x00") else back[0..r];
    if (!std.mem.eql(u8, have, expect)) return error.StreamDecryptDiffers;
    StreamMark.mark(switch (padding) {
        .none => .none,
        .pkcs7 => .pkcs7,
        .ansi_x923 => .ansi_x923,
        .iso7816 => .iso7816,
        .zero => .zero,
    });
    if (pieces > 1) StreamMark.mark(.split);

    if (padding == .none and len > 0) {
        var e2 = aescbc.StreamEncryptor(Aes, .none).init(&key, iv);
        _ = try e2.update(msg[0 .. len - 1], &got);
        if (e2.finish(&got)) |_| return error.UnalignedAccepted else |er| if (er != error.NotBlockAligned) return error.WrongError;
        StreamMark.mark(.unaligned_refused);
    }
    if (padding == .pkcs7 or padding == .ansi_x923 or padding == .iso7816) {
        // A last block that decrypts to garbage: refused (with overwhelming
        // probability; a garbage block that happens to be valid is accepted
        // by every implementation, so only a refusal counts here).
        var bad = want;
        bad[plen - 1] ^= 0xff;
        var d2 = aescbc.StreamDecryptor(Aes, padding).init(&key, iv);
        _ = try d2.update(bad[0..plen], &back);
        if (d2.finish(&back)) |_| {} else |er| {
            if (er != error.InvalidPadding) return error.WrongError;
            StreamMark.mark(.bad_padding_refused);
        }
    }
}

fn fuzzStream(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [128]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    switch (k.ranged(0, 4)) {
        0 => try streamCase(.none, &k),
        1 => try streamCase(.pkcs7, &k),
        2 => try streamCase(.ansi_x923, &k),
        3 => try streamCase(.iso7816, &k),
        else => try streamCase(.zero, &k),
    }
}
