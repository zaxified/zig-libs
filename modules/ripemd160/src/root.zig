// SPDX-License-Identifier: MIT
//! ripemd160 — RIPEMD-160 (ISO/IEC 10118-3), the Dobbertin–Bosselaers–Preneel hash.
//!
//! std has no RIPEMD-160. This module fills that gap with a std-crypto-style API
//! (`init`/`update`/`final`, one-shot `hash`) plus `hash160` — the Bitcoin
//! primitive `RIPEMD160(SHA256(msg))` used to derive P2PKH/P2WPKH pubkey hashes,
//! composed from this module's compressor and `std.crypto.hash.sha2.Sha256`.
//!
//!
//! **Zeroization: none, deliberately (CONVENTIONS §2.1 Z3).** The chaining
//! state and the message-block buffer are the internal working state of a
//! transform, not a secret this module owns — they are Z3, the class the repo
//! settled once so it stops being re-raised module by module. `std` takes the
//! same position: `sha2`, `sha3`, `blake2`, `blake3`, `hmac` and `hkdf` contain
//! no `secureZero` at all (`hmac` holds a real MAC key in `o_key_pad` and still
//! does not wipe it), while `keccak_p`/`ascon` expose an opt-in `secureZero()`
//! their own hash paths never call. The technical reason is in §2.1: the
//! compression function keeps these words in registers and spill slots for its
//! whole run, and no `secureZero` reaches those, so wiping the struct clears
//! the copy least likely to be the one that leaks. A caller with a concrete
//! reason to want the state cleared should say so and get an opt-in
//! `secureZero()` here — that is a feature request, not a defect report.
//! RIPEMD-160 processes 512-bit blocks through two independent, parallel
//! 80-round lines (five 16-round groups each, distinct nonlinear functions,
//! word-selection permutations, and rotate amounts per line) whose final
//! states are combined into the next chaining value — unlike SHA-2's single
//! line. Length padding is **little-endian** (like MD5), the opposite of
//! SHA-1/SHA-2's big-endian — the classic implementation bug this module's
//! million-'a' KAT (§ RFC/spec Appendix, via the streaming update path) guards
//! against: a wrong-endian length only diverges from the correct digest once
//! the message is long enough to make the low length byte matter, which the
//! single-block "abc"-sized vectors cannot catch.
//!
//! Provenance: original work of the zig-libs authors (MIT); the algorithm is
//! the public RIPEMD-160 specification (H. Dobbertin, A. Bosselaers, B.
//! Preneel, "RIPEMD-160: A Strengthened Version of RIPEMD", 1996; also
//! ISO/IEC 10118-3) — ported clean-room from the published round tables /
//! constants, no third-party source consulted or copied. Model after Go
//! `golang.org/x/crypto/ripemd160`'s streaming shape and this repo's own
//! `std.crypto.hash.md5.Md5` (structurally closest std hash: LE length
//! padding, `buf`/`buf_len`/`total_len` streaming cache).

const std = @import("std");
const mem = std.mem;
const math = std.math;

pub const meta = .{
    .platform = .any, // pure computation, no OS calls
    .role = .util,
    .concurrency = .reentrant, // Ripemd160 is a plain value type; no shared state
    .model_after = "RIPEMD-160 spec (Dobbertin/Bosselaers/Preneel, ISO/IEC 10118-3); streaming shape after std.crypto.hash.md5.Md5",
    .deps = .{},
};

// ── round tables (spec Appendix / ISO 10118-3) ──────────────────────────────

/// Message-word selection, left line: r[j].
const R: [80]u4 = .{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};

/// Message-word selection, right line: r'[j].
const RP: [80]u4 = .{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};

/// Rotate-left amounts, left line: s[j].
const S: [80]u5 = .{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};

/// Rotate-left amounts, right line: s'[j].
const SP: [80]u5 = .{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};

/// Additive constants, left line, per 16-round group.
const K_GROUP: [5]u32 = .{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };

/// Additive constants, right line, per 16-round group.
const KP_GROUP: [5]u32 = .{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

/// The five RIPEMD-160 nonlinear round functions, indexed 0..4 (f1..f5).
/// Left line uses group order f1,f2,f3,f4,f5; right line uses the mirror
/// f5,f4,f3,f2,f1 for the same 16-round ranges (see `compress`).
fn roundFn(group: u3, x: u32, y: u32, z: u32) u32 {
    return switch (group) {
        0 => x ^ y ^ z, // f1
        1 => (x & y) | (~x & z), // f2
        2 => (x | ~y) ^ z, // f3
        3 => (x & z) | (y & ~z), // f4
        4 => x ^ (y | ~z), // f5
        else => unreachable,
    };
}

// ── Ripemd160 ────────────────────────────────────────────────────────────────

/// RIPEMD-160: `init()` → `update(bytes)` (any number of times) → `final(*[20]u8)`.
/// Streaming cache mirrors `std.crypto.hash.md5.Md5` (`buf`/`buf_len`/`total_len`);
/// length padding is little-endian, matching RIPEMD-160's spec (not SHA-2's BE).
pub const Ripemd160 = struct {
    const Self = @This();
    pub const block_length = 64;
    pub const digest_length = 20;
    pub const Options = struct {};

    h: [5]u32,
    buf: [64]u8,
    buf_len: u8,
    total_len: u64,

    pub fn init(options: Options) Self {
        _ = options;
        return .{
            .h = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    /// One-shot: hash `data` into `out`.
    pub fn hash(data: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Self.init(options);
        d.update(data);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Fill it and process.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);
            d.compress(&d.buf);
            d.buf_len = 0;
        }

        // Full middle blocks straight from the input.
        while (off + 64 <= b.len) : (off += 64) {
            d.compress(b[off..][0..64]);
        }

        // Stash any remainder for next call / final.
        const rem = b[off..];
        @memcpy(d.buf[d.buf_len..][0..rem.len], rem);
        d.buf_len += @intCast(rem.len);

        d.total_len +%= b.len;
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // Buffer is never completely full here (compress drains at 64).
        @memset(d.buf[d.buf_len..], 0);

        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        // Not enough room for the 8-byte length: pad+compress this block,
        // then start a fresh zero block for the length.
        if (64 - d.buf_len < 8) {
            d.compress(&d.buf);
            @memset(d.buf[0..], 0);
        }

        // RIPEMD-160 length suffix is little-endian bit count (unlike SHA-2's BE).
        const bit_len: u64 = d.total_len *% 8;
        mem.writeInt(u64, d.buf[56..64], bit_len, .little);

        d.compress(&d.buf);

        for (d.h, 0..) |word, i| mem.writeInt(u32, out[4 * i ..][0..4], word, .little);
    }

    /// Process one 512-bit (64-byte) block: the two parallel 80-round lines,
    /// combined into the next chaining value. See the RIPEMD-160 spec.
    fn compress(d: *Self, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        for (0..16) |i| x[i] = mem.readInt(u32, block[i * 4 ..][0..4], .little);

        var a: u32 = d.h[0];
        var b: u32 = d.h[1];
        var c: u32 = d.h[2];
        var dd: u32 = d.h[3];
        var e: u32 = d.h[4];

        var aa: u32 = d.h[0];
        var bb: u32 = d.h[1];
        var cc: u32 = d.h[2];
        var ddd: u32 = d.h[3];
        var ee: u32 = d.h[4];

        var j: usize = 0;
        while (j < 80) : (j += 1) {
            const group: u3 = @intCast(j / 16);

            // Left line.
            const f = roundFn(group, b, c, dd);
            const k = K_GROUP[group];
            var t = math.rotl(u32, a +% f +% x[R[j]] +% k, @as(u5, S[j])) +% e;
            a = e;
            e = dd;
            dd = math.rotl(u32, c, 10);
            c = b;
            b = t;

            // Right line — mirrored function group order (f5..f1).
            const groupp: u3 = 4 - group;
            const fp = roundFn(groupp, bb, cc, ddd);
            const kp = KP_GROUP[group];
            t = math.rotl(u32, aa +% fp +% x[RP[j]] +% kp, @as(u5, SP[j])) +% ee;
            aa = ee;
            ee = ddd;
            ddd = math.rotl(u32, cc, 10);
            cc = bb;
            bb = t;
        }

        const t = d.h[1] +% c +% ddd;
        d.h[1] = d.h[2] +% dd +% ee;
        d.h[2] = d.h[3] +% e +% aa;
        d.h[3] = d.h[4] +% a +% bb;
        d.h[4] = d.h[0] +% b +% cc;
        d.h[0] = t;
    }
};

// ── hash160 ──────────────────────────────────────────────────────────────────

/// `RIPEMD160(SHA256(data))` — the Bitcoin pubkey-hash / script-hash primitive
/// (P2PKH/P2WPKH/P2SH addresses). Composes `std.crypto.hash.sha2.Sha256` with
/// this module's `Ripemd160`; no allocation.
pub fn hash160(data: []const u8, out: *[Ripemd160.digest_length]u8) void {
    var sha: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &sha, .{});
    Ripemd160.hash(&sha, out, .{});
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectHex(hex: []const u8, digest: [Ripemd160.digest_length]u8) !void {
    const got = std.fmt.bytesToHex(digest, .lower);
    try testing.expectEqualStrings(hex, &got);
}

// Official RIPEMD-160 test vectors (spec Appendix / widely republished, e.g.
// the Bosselaers reference page); cross-checked locally against both
// `openssl dgst -rmd160` and Python's `hashlib.new('ripemd160')` while
// authoring this module.
const Kat = struct { msg: []const u8, hex: *const [40]u8 };
const kats = [_]Kat{
    .{ .msg = "", .hex = "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
    .{ .msg = "a", .hex = "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe" },
    .{ .msg = "abc", .hex = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
    .{ .msg = "message digest", .hex = "5d0689ef49d2fae572b881b123a85ffa21595f36" },
    .{ .msg = "abcdefghijklmnopqrstuvwxyz", .hex = "f71c27109c692c1b56bbdceb5b9d2865b3708dbc" },
    .{
        .msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        .hex = "b0e20b6e3116640286ed3a87a5713079b21f5189",
    },
    .{
        .msg = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        .hex = "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
    },
};

test "official RIPEMD-160 test vectors, one-shot" {
    var out: [Ripemd160.digest_length]u8 = undefined;
    for (kats) |v| {
        Ripemd160.hash(v.msg, &out, .{});
        try expectHex(v.hex, out);
    }
}

test "million 'a' vector — LE-length padding stress" {
    // The classic RIPEMD-160 stress vector: 1,000,000 repetitions of 'a', fed
    // in chunks so both the multi-block compress loop and the LE length
    // suffix (the historic RIPEMD/SHA endian mixup bug) are exercised.
    var d = Ripemd160.init(.{});
    var chunk: [1000]u8 = [_]u8{'a'} ** 1000;
    for (0..1000) |_| d.update(&chunk);
    var out: [Ripemd160.digest_length]u8 = undefined;
    d.final(&out);
    try expectHex("52783243c1697bdbe16d37f97f68f08325dc1528", out);

    // one-shot over the same 1,000,000 bytes must agree
    const gpa = testing.allocator;
    const big = try gpa.alloc(u8, 1_000_000);
    defer gpa.free(big);
    @memset(big, 'a');
    var out2: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(big, &out2, .{});
    try testing.expectEqualSlices(u8, &out, &out2);
}

test "final() padding boundary: message length 55 (mod 64) needs no extra block" {
    // buf_len after the 0x80 terminator is exactly 56, leaving exactly the 8
    // bytes needed for the LE length suffix — the single-block path, not the
    // "pad+compress, then a fresh zero block" path `final` takes when there
    // isn't room. None of the other vectors' lengths land exactly here.
    // Reference computed independently with both Python hashlib and
    // `openssl dgst -rmd160` (agree).
    var msg: [55]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @intCast(i % 251);
    var out: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(&msg, &out, .{});
    try expectHex("3c86963b3ff646a65ae42996e9664c747cc7e5e6", out);
}

test "streaming: chunked update equals one-shot, across block boundaries" {
    for (kats) |v| {
        var one_shot: [Ripemd160.digest_length]u8 = undefined;
        Ripemd160.hash(v.msg, &one_shot, .{});

        // feed byte-by-byte
        var d = Ripemd160.init(.{});
        for (v.msg) |byte| d.update(&[_]u8{byte});
        var streamed: [Ripemd160.digest_length]u8 = undefined;
        d.final(&streamed);
        try testing.expectEqualSlices(u8, &one_shot, &streamed);
    }

    // a message straddling the 64-byte block boundary, fed in uneven chunks
    var msg: [200]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @intCast(i % 251);

    var one_shot: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(&msg, &one_shot, .{});

    var d = Ripemd160.init(.{});
    d.update(msg[0..1]);
    d.update(msg[1..63]);
    d.update(msg[63..64]); // exactly fills a block
    d.update(msg[64..130]);
    d.update(msg[130..200]);
    var streamed: [Ripemd160.digest_length]u8 = undefined;
    d.final(&streamed);
    try testing.expectEqualSlices(u8, &one_shot, &streamed);
}

test "empty update calls are no-ops" {
    var d = Ripemd160.init(.{});
    d.update("");
    d.update("abc");
    d.update("");
    var out: [Ripemd160.digest_length]u8 = undefined;
    d.final(&out);
    try expectHex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", out);
}

test "hash160: RIPEMD160(SHA256(x)) composition, known Bitcoin-corpus vector" {
    // A real secp256k1 compressed pubkey (33 bytes) and its hash160, computed
    // locally with `openssl ecparam -genkey` + `openssl dgst -sha256` piped
    // into `openssl dgst -rmd160` while authoring this module — the same
    // SHA256∘RIPEMD160 composition Bitcoin uses to derive a P2PKH/P2WPKH
    // pubkey hash from a compressed pubkey.
    const pubkey_hex = "025dfb6b67f1a3dd5ec911d2f82e783b471c3e3df450f91e26598af57a25a64700";
    var pubkey: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&pubkey, pubkey_hex) catch unreachable;

    var out: [Ripemd160.digest_length]u8 = undefined;
    hash160(&pubkey, &out);
    try expectHex("7d88a8cb551e2e72e41ae82f29bbdd78f31e309f", out);
}

test "hash160: matches manual SHA256 then RIPEMD160 composition" {
    const msg = "the quick brown fox";
    var sha: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &sha, .{});
    var manual: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(&sha, &manual, .{});

    var via_fn: [Ripemd160.digest_length]u8 = undefined;
    hash160(msg, &via_fn);

    try testing.expectEqualSlices(u8, &manual, &via_fn);
}

test "block_length / digest_length" {
    try testing.expectEqual(@as(usize, 64), Ripemd160.block_length);
    try testing.expectEqual(@as(usize, 20), Ripemd160.digest_length);
}

// ── fuzz: streaming `update` agrees with one-shot `hash`, at any split ─────
//
// W2 A3 (F1): CLASS B, zero `testing.fuzz(` harnesses — this module was
// absent from `scripts/fuzz-sweep.sh`'s target list entirely. Per the
// campaign brief, a crypto primitive's byte-exactness is already pinned by
// the KATs above (including the LE-length-padding stress vector); fuzzing
// it again would duplicate that, not add to it. What the KATs do NOT cover
// is `update`'s own buffer arithmetic — the partial-buffer fill, the
// full-block loop, and the remainder copy that has to stay correct across
// however many calls and however the caller chops the message up. The
// existing "streaming: chunked update equals one-shot" test only tries a
// handful of hand-picked split points; this harness tries however many the
// input asks for, at byte-by-byte granularity, up to several block
// boundaries.
//
// Oracle: streaming `update`/`final` must equal one-shot `hash` on the same
// bytes. This is a differential between two genuinely different code paths
// (the multi-call buffering logic vs. the straight-through compress loop in
// `hash`), not a round trip of one function against itself — but per the
// campaign brief's own caveat, a mutation that changes both paths
// *consistently* (e.g. a shared bug in `compress`) would still be invisible
// to this oracle; the KATs above are what pin `compress` itself against an
// external reference.
test "fuzz: streaming update matches one-shot hash, at every split the input picks" {
    try testing.fuzz({}, fuzzStreamingMatchesOneShot, .{});
}

fn fuzzStreamingMatchesOneShot(_: void, smith: *testing.Smith) !void {
    // Length drawn first so every mutated byte lands inside `data`, not
    // scattered across a fixed 4096-byte draw a small `len` would discard.
    var msg: [4096]u8 = undefined;
    const len = smith.valueRangeAtMost(u16, 0, msg.len);
    smith.bytes(msg[0..len]);
    const data = msg[0..len];

    var one_shot: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(data, &one_shot, .{});

    // Feed `data` through `update` in fuzzer-chosen chunk sizes (1..97 bytes,
    // deliberately not a divisor of the 64-byte block so both the
    // straddling-a-boundary and the landing-exactly-on-one shapes occur).
    var d = Ripemd160.init(.{});
    var off: usize = 0;
    while (off < data.len) {
        const chunk = smith.valueRangeAtMost(u8, 1, 97);
        const n = @min(chunk, data.len - off);
        d.update(data[off..][0..n]);
        off += n;
    }
    var streamed: [Ripemd160.digest_length]u8 = undefined;
    d.final(&streamed);

    try testing.expectEqualSlices(u8, &one_shot, &streamed);
}
