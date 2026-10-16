// SPDX-License-Identifier: MIT

//! aescbc — raw AES-CBC block-cipher mode (NIST SP800-38A §6.2) over any
//! std-shaped AES type (`std.crypto.core.aes`'s `Aes128`/`Aes256`, the
//! `aes192` module's `Aes192`), plus the two padding schemes
//! that consumers in this repo compose CBC with.
//!
//! `std.crypto.core.aes` (Zig 0.16) ships the AES block cipher but no CBC
//! mode — CBC has been hand-rolled independently in `xmlenc` (XML-Encryption
//! content decryption, W3C xmlenc padding) and `jwe` (`A128CBC-HS256` /
//! `A256CBC-HS512`, RFC 7518 §5.2, PKCS#7 padding). This module extracts a
//! single well-tested core so both can collapse onto it.
//!
//! **AES-192:** std 0.16 has no `Aes192`; pass the `aes192` module's
//! `Aes192` (same declarations as std's two). This module is comptime-generic
//! over the cipher type, so it needed no code change for it — only the
//! SP800-38A F.2.3/F.2.4 KATs (2026-10-10).
//!
//! See SPEC.md for the padding-oracle caveat and which consumer uses which
//! padding scheme.

const std = @import("std");
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "AES-CBC (NIST SP800-38A): one-shot, incremental, streaming with six paddings, ciphertext stealing CS1-3; zero-alloc; padding-oracle caveat — consumers own authenticate-before-unpad",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "NIST SP800-38A §6.2 (CBC mode); RFC 5652 §6.3 (PKCS#7 padding); W3C XML-Encryption Syntax and Processing 1.1 §5.2 (xmlenc padding)",
    .deps = .{},
};

/// AES block size in bytes (fixed at 128 bits regardless of key length).
pub const block_len = 16;

/// Raw-CBC errors (no padding involved).
pub const Error = error{
    /// `plaintext`/`ciphertext` length is not a multiple of `block_len`.
    /// Raw CBC only operates on block-aligned buffers; pad first.
    NotBlockAligned,
    /// `out` is smaller than the input.
    BufferTooSmall,
};

/// Padding-helper errors. Deliberately a single generic member: CBC padding
/// oracles (Vaudenay) are built by distinguishing *why* an unpad failed, so
/// every malformed-padding shape below collapses to this one error — never
/// branch a caller's control flow on anything more specific. See SPEC.md.
pub const PaddingError = error{InvalidPadding};

/// Encrypt `plaintext` (must be `block_len`-aligned) into `out` under raw
/// CBC: `C[0] = E(P[0] XOR IV)`, `C[i] = E(P[i] XOR C[i-1])`. `Aes` is
/// `std.crypto.core.aes.Aes128`/`Aes256` or `aes192.Aes192`; `key` points to
/// `[Aes.key_bits / 8]u8` (BREAKING 2026-10-09: by pointer, so no key copy is
/// left in the caller's frame; the body runs under a dead-stack burn). `out` must be at least `plaintext.len` bytes.
/// No allocation. Returns the written length (== `plaintext.len`).
/// Zeroization posture (CONVENTIONS §2.1): nothing here is wiped, deliberately.
/// The AES round-key schedule (`Aes.initEnc`/`initDec`'s context) and the
/// per-block staging buffers are Z3 — the internal working state of a
/// transform, which `std`'s own `core.aes` does not wipe either. `key` and `iv`
/// arrive from caller-owned storage (Z2): the caller wipes those, and
/// the plaintext/ciphertext live in the caller's `out`/input slices, which the
/// caller likewise owns. This module allocates nothing and holds nothing across
/// calls, so it has no Z1 storage at all.
pub fn encrypt(
    comptime Aes: type,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    plaintext: []const u8,
    out: []u8,
) Error!usize {
    return burn.run(burn.cbc_burn, Error!usize, encryptBody, .{ Aes, key, iv, plaintext, out });
}

fn encryptBody(
    comptime Aes: type,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    plaintext: []const u8,
    out: []u8,
) Error!usize {
    try checkLens(plaintext.len, out.len);
    const ctx = Aes.initEnc(key.*);
    var chain = iv;
    encryptChain(&ctx, &chain, plaintext, out);
    return plaintext.len;
}

fn checkLens(in_len: usize, out_len: usize) Error!void {
    if (in_len % block_len != 0) return error.NotBlockAligned;
    if (out_len < in_len) return error.BufferTooSmall;
}

const V = @Vector(block_len, u8);

/// The chain itself, shared by the one-shot and the stateful API: one block at
/// a time (each input is the previous output, so nothing can run in parallel).
/// `out` may be `in` itself: each block is read before it is written.
fn encryptChain(ctx: anytype, chain: *[block_len]u8, in: []const u8, out: []u8) void {
    var prev: V = chain.*;
    var i: usize = 0;
    while (i < in.len) : (i += block_len) {
        var block: [block_len]u8 = @as(V, in[i..][0..block_len].*) ^ prev;
        ctx.encrypt(&block, &block);
        out[i..][0..block_len].* = block;
        prev = block;
    }
    chain.* = prev;
}

/// Blocks decrypted per `decryptWide` call: std's own choice for this CPU
/// (8 on current x86-64 AES-NI cores, the depth OpenSSL's `aesni_cbc_encrypt`
/// decrypt path pipelines too).
const wide = std.crypto.core.aes.Block.parallel.optimal_parallel_blocks;

/// Decryption has no chain through the cipher -- `P[i] = D(C[i]) ^ C[i-1]` --
/// so `wide` blocks go through `decryptWide` at once. Every ciphertext block a
/// group needs is read (into `tmp` and `next`) before any of the group's output
/// is written, so `out` may be `in` itself.
fn decryptChain(ctx: anytype, chain: *[block_len]u8, in: []const u8, out: []u8) void {
    var prev: [block_len]u8 = chain.*;
    var i: usize = 0;
    while (in.len - i >= wide * block_len) : (i += wide * block_len) {
        const src = in[i..][0 .. wide * block_len];
        var tmp: [wide * block_len]u8 = undefined;
        ctx.decryptWide(wide, &tmp, src);
        const next: [block_len]u8 = src[(wide - 1) * block_len ..][0..block_len].*;
        var x: @Vector(wide * block_len, u8) = tmp;
        x ^= @as(@Vector(wide * block_len, u8), prev ++ src[0 .. (wide - 1) * block_len].*);
        out[i..][0 .. wide * block_len].* = x;
        prev = next;
    }
    while (i < in.len) : (i += block_len) {
        const ct: [block_len]u8 = in[i..][0..block_len].*;
        var pt: [block_len]u8 = undefined;
        ctx.decrypt(&pt, &ct);
        out[i..][0..block_len].* = @as(V, pt) ^ @as(V, prev);
        prev = ct;
    }
    chain.* = prev;
}

/// Decrypt `ciphertext` (must be `block_len`-aligned) into `out` under raw
/// CBC: `P[0] = D(C[0]) XOR IV`, `P[i] = D(C[i]) XOR C[i-1]`. Same `Aes`/
/// `key`/`iv` contract as `encrypt`. No allocation, no padding stripped —
/// pair with `unpadPkcs7`/`unpadXmlEnc` as needed. Returns the written
/// length (== `ciphertext.len`).
pub fn decrypt(
    comptime Aes: type,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    ciphertext: []const u8,
    out: []u8,
) Error!usize {
    return burn.run(burn.cbc_burn, Error!usize, decryptBody, .{ Aes, key, iv, ciphertext, out });
}

fn decryptBody(
    comptime Aes: type,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    ciphertext: []const u8,
    out: []u8,
) Error!usize {
    try checkLens(ciphertext.len, out.len);
    const ctx = Aes.initDec(key.*);
    var chain = iv;
    decryptChain(&ctx, &chain, ciphertext, out);
    return ciphertext.len;
}

// ── Ciphertext stealing (NIST SP800-38A Addendum, 2010) ──────────────────────
//
// CBC for any length >= one block, ciphertext as long as the plaintext: the
// last, partial block P_n* (d octets, 1..16) is zero-filled to P_n, encrypted
// on top of C_{n-1}, and only the first d octets of C_{n-1} are kept. The three
// variants differ only in the order of the last two ciphertext pieces:
// CS1 `.. C_{n-1}* C_n`; CS2 `.. C_n C_{n-1}*` unless d == 16 (then plain
// CBC); CS3 `.. C_n C_{n-1}*` always (Kerberos, RFC 3962 -- it swaps even full
// blocks). Every variant of a one-block message is plain CBC. OpenSSL 3's
// `AES-*-CBC-CTS` (`cts_mode` CS1/CS2/CS3) and RustCrypto's `cts` crate ship
// the same three.

pub const CtsVariant = enum { cs1, cs2, cs3 };

pub const CtsError = error{
    /// Ciphertext stealing needs at least one whole block.
    TooShort,
    /// `out` is smaller than the input.
    BufferTooSmall,
};

/// Encrypt `plaintext` (any length >= `block_len`) into `out` (at least as
/// long; may be `plaintext` itself) under CBC with ciphertext stealing.
/// Returns `plaintext.len`. Same `Aes`/`key`/`iv` contract as `encrypt`.
pub fn encryptCts(
    comptime Aes: type,
    variant: CtsVariant,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    plaintext: []const u8,
    out: []u8,
) CtsError!usize {
    return burn.run(burn.cts_burn, CtsError!usize, encryptCtsBody, .{ Aes, variant, key, iv, plaintext, out });
}

fn encryptCtsBody(
    comptime Aes: type,
    variant: CtsVariant,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    in: []const u8,
    out: []u8,
) CtsError!usize {
    if (in.len < block_len) return error.TooShort;
    if (out.len < in.len) return error.BufferTooSmall;
    const ctx = Aes.initEnc(key.*);
    var chain = iv;
    if (in.len == block_len) {
        encryptChain(&ctx, &chain, in, out);
        return in.len;
    }
    // n blocks, the last one d octets long; the first n-2 are plain CBC.
    const n = (in.len + block_len - 1) / block_len;
    const d = in.len - (n - 1) * block_len;
    const head = (n - 2) * block_len;
    encryptChain(&ctx, &chain, in[0..head], out[0..head]);
    var p_last: [block_len]u8 = @splat(0);
    @memcpy(p_last[0..d], in[head + block_len ..][0..d]);
    var c_prev: [block_len]u8 = @as(V, in[head..][0..block_len].*) ^ @as(V, chain);
    ctx.encrypt(&c_prev, &c_prev);
    var c_last: [block_len]u8 = @as(V, p_last) ^ @as(V, c_prev);
    ctx.encrypt(&c_last, &c_last);
    const swap = switch (variant) {
        .cs1 => false,
        .cs2 => d != block_len,
        .cs3 => true,
    };
    if (swap) {
        out[head..][0..block_len].* = c_last;
        @memcpy(out[head + block_len ..][0..d], c_prev[0..d]);
    } else {
        @memcpy(out[head..][0..d], c_prev[0..d]);
        out[head + d ..][0..block_len].* = c_last;
    }
    return in.len;
}

/// Decrypt `ciphertext` (any length >= `block_len`) produced by `encryptCts`
/// with the same `variant` into `out` (may be `ciphertext` itself). Returns
/// `ciphertext.len`. Unauthenticated, like all of CBC: see the padding-oracle
/// caveat in SPEC.md (there is no padding to probe, but a flipped bit still
/// lands where CBC puts it).
pub fn decryptCts(
    comptime Aes: type,
    variant: CtsVariant,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    ciphertext: []const u8,
    out: []u8,
) CtsError!usize {
    return burn.run(burn.cts_burn, CtsError!usize, decryptCtsBody, .{ Aes, variant, key, iv, ciphertext, out });
}

fn decryptCtsBody(
    comptime Aes: type,
    variant: CtsVariant,
    key: *const [Aes.key_bits / 8]u8,
    iv: [block_len]u8,
    in: []const u8,
    out: []u8,
) CtsError!usize {
    if (in.len < block_len) return error.TooShort;
    if (out.len < in.len) return error.BufferTooSmall;
    const ctx = Aes.initDec(key.*);
    var chain = iv;
    if (in.len == block_len) {
        decryptChain(&ctx, &chain, in, out);
        return in.len;
    }
    const n = (in.len + block_len - 1) / block_len;
    const d = in.len - (n - 1) * block_len;
    const head = (n - 2) * block_len;
    const swap = switch (variant) {
        .cs1 => false,
        .cs2 => d != block_len,
        .cs3 => true,
    };
    // Both tail pieces into locals first: `out` may alias `in`.
    var c_prev: [block_len]u8 = undefined; // C_{n-1}, completed below
    var c_last: [block_len]u8 = undefined; // C_n
    if (swap) {
        c_last = in[head..][0..block_len].*;
        @memcpy(c_prev[0..d], in[head + block_len ..][0..d]);
    } else {
        @memcpy(c_prev[0..d], in[head..][0..d]);
        c_last = in[head + d ..][0..block_len].*;
    }
    decryptChain(&ctx, &chain, in[0..head], out[0..head]);
    // D(C_n) = C_{n-1} ^ (P_n* || 0...): its tail IS the stolen tail of C_{n-1}.
    var z: [block_len]u8 = undefined;
    ctx.decrypt(&z, &c_last);
    @memcpy(c_prev[d..], z[d..]);
    var p_prev: [block_len]u8 = undefined;
    ctx.decrypt(&p_prev, &c_prev);
    out[head..][0..block_len].* = @as(V, p_prev) ^ @as(V, chain);
    for (out[head + block_len ..][0..d], z[0..d], c_prev[0..d]) |*o, a, b| o.* = a ^ b;
    return in.len;
}

// ── Incremental CBC (Go `cipher.BlockMode`, RustCrypto `cbc::Encryptor`) ────

/// CBC encryption under one key schedule, kept across calls: `init` expands the
/// key once, every `update` continues the chain where the previous one ended
/// (Go's `CryptBlocks`), and `setIv` starts a new message under the same key
/// (Go's `SetIV`) -- so a stream can be fed in block-aligned pieces, and many
/// messages share one key schedule. `update(a ++ b)` == `update(a); update(b)`.
/// The struct holds the AES round keys (Z3, CONVENTIONS §2.1: not wiped by
/// `update`); a caller that wants them gone calls `wipe()` when done.
pub fn Encryptor(comptime Aes: type) type {
    return struct {
        const Self = @This();
        ctx: @TypeOf(Aes.initEnc(undefined)),
        chain: [block_len]u8,

        /// The schedule by value. Its first round keys ARE key bytes, so the
        /// returned copy can outlive the burn in this frame; where that
        /// matters, `initInto` writes it straight into the caller's struct.
        pub fn init(key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) Self {
            var self: Self = undefined;
            initInto(&self, key, iv);
            return self;
        }

        pub fn initInto(out: *Self, key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) void {
            burn.run(burn.schedule_burn, void, initBody, .{ out, key, iv });
        }
        fn initBody(out: *Self, key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) void {
            out.* = .{ .ctx = Aes.initEnc(key.*), .chain = iv };
        }

        /// Start a new message under the same key.
        pub fn setIv(self: *Self, iv: [block_len]u8) void {
            self.chain = iv;
        }

        /// Encrypt the block-aligned `in` into `out` (`out.len >= in.len`;
        /// `out` may be `in` itself, not a partial overlap), continuing the
        /// chain. Returns `in.len`. On an error nothing is written and the
        /// chain is unchanged.
        pub fn update(self: *Self, in: []const u8, out: []u8) Error!usize {
            try checkLens(in.len, out.len);
            burn.run(burn.update_burn, void, encryptChain, .{ &self.ctx, &self.chain, in, out });
            return in.len;
        }

        /// Zero the round keys and the chain (opt-in, see the type's doc).
        pub fn wipe(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }
    };
}

/// CBC decryption under one key schedule, kept across calls; the mirror of
/// `Encryptor` (same `init`/`setIv`/`update`/`wipe` contract). Decryption
/// pipelines `wide` blocks per step, so long `update`s are several times
/// faster per byte than encryption.
pub fn Decryptor(comptime Aes: type) type {
    return struct {
        const Self = @This();
        ctx: @TypeOf(Aes.initDec(undefined)),
        chain: [block_len]u8,

        /// The schedule by value. Its first round keys ARE key bytes, so the
        /// returned copy can outlive the burn in this frame; where that
        /// matters, `initInto` writes it straight into the caller's struct.
        pub fn init(key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) Self {
            var self: Self = undefined;
            initInto(&self, key, iv);
            return self;
        }

        pub fn initInto(out: *Self, key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) void {
            burn.run(burn.schedule_burn, void, initBody, .{ out, key, iv });
        }
        fn initBody(out: *Self, key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) void {
            out.* = .{ .ctx = Aes.initDec(key.*), .chain = iv };
        }

        pub fn setIv(self: *Self, iv: [block_len]u8) void {
            self.chain = iv;
        }

        pub fn update(self: *Self, in: []const u8, out: []u8) Error!usize {
            try checkLens(in.len, out.len);
            burn.run(burn.update_burn, void, decryptChain, .{ &self.ctx, &self.chain, in, out });
            return in.len;
        }

        pub fn wipe(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }
    };
}

// ── Streaming with padding (OpenSSL `EVP_*Update` + `EVP_*Final`) ───────────

/// The padding a `StreamEncryptor`/`StreamDecryptor` applies in `finish`.
/// `none` = the message must come out block-aligned (`NotBlockAligned`
/// otherwise); ISO 10126 is decrypt-compatible with `unpadXmlEnc` and needs a
/// random source to encrypt, so it is offered through the one-shot helpers only.
pub const Padding = enum { none, pkcs7, ansi_x923, iso7816, zero };

pub const StreamError = Error || PaddingError;

/// CBC encryption fed in pieces of ANY length: `update` encrypts every whole
/// block it has and keeps the rest (< 16 octets); `finish` pads that tail
/// with `padding` and encrypts it. `update` writes at most
/// `maxUpdateLen(in.len)` octets, `finish` at most `block_len`. `out` must
/// not overlap `in` (a buffered tail shifts the output ahead of the input).
/// `setIv` starts a new message. Holds the round keys like `Encryptor`.
pub fn StreamEncryptor(comptime Aes: type, comptime padding: Padding) type {
    return Stream(Aes, padding, .encrypt);
}

/// The mirror of `StreamEncryptor`. With a padding other than `none` it holds
/// back the last whole block until `finish`, which decrypts it, checks and
/// strips the padding (`InvalidPadding`, one error for every malformed shape)
/// and writes what is left (0..16 octets). Unauthenticated: decrypt only
/// what was authenticated first -- see the padding-oracle caveat in SPEC.md.
pub fn StreamDecryptor(comptime Aes: type, comptime padding: Padding) type {
    return Stream(Aes, padding, .decrypt);
}

fn Stream(comptime Aes: type, comptime padding: Padding, comptime dir: enum { encrypt, decrypt }) type {
    return struct {
        const Self = @This();
        const Inner = if (dir == .encrypt) Encryptor(Aes) else Decryptor(Aes);
        /// Decryption keeps a whole block back when `finish` must unpad it.
        const hold = dir == .decrypt and padding != .none;

        inner: Inner,
        tail: [block_len]u8 = undefined,
        tail_len: usize = 0,

        pub fn init(key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) Self {
            var self: Self = undefined;
            initInto(&self, key, iv);
            return self;
        }

        pub fn initInto(out: *Self, key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) void {
            burn.run(burn.schedule_burn, void, initBody, .{ out, key, iv });
        }
        fn initBody(out: *Self, key: *const [Aes.key_bits / 8]u8, iv: [block_len]u8) void {
            out.inner.initInto(key, iv);
            out.tail_len = 0;
        }

        /// Start a new message under the same key (drops a buffered tail).
        pub fn setIv(self: *Self, iv: [block_len]u8) void {
            self.inner.setIv(iv);
            self.tail_len = 0;
        }

        /// Octets the next `update(in)` writes for an `in` of `in_len`.
        pub fn maxUpdateLen(self: *const Self, in_len: usize) usize {
            const avail = self.tail_len + in_len;
            if (!hold) return avail / block_len * block_len;
            return if (avail == 0) 0 else (avail - 1) / block_len * block_len;
        }

        /// Process `in`, write every block that is complete (and, decrypting
        /// with padding, not the last one seen so far) to `out`. Returns the
        /// octets written. On `BufferTooSmall` nothing changes.
        pub fn update(self: *Self, in: []const u8, out: []u8) Error!usize {
            const emit = self.maxUpdateLen(in.len);
            if (out.len < emit) return error.BufferTooSmall;
            var at: usize = 0; // octets of `in` consumed
            var w: usize = 0;
            if (emit > 0 and self.tail_len > 0) {
                const take = block_len - self.tail_len;
                @memcpy(self.tail[self.tail_len..], in[0..take]);
                _ = try self.inner.update(&self.tail, out[0..block_len]);
                at = take;
                w = block_len;
                self.tail_len = 0;
            }
            if (emit > w) {
                const mid = emit - w;
                _ = try self.inner.update(in[at..][0..mid], out[w..][0..mid]);
                at += mid;
                w = emit;
            }
            const rest = in[at..];
            @memcpy(self.tail[self.tail_len..][0..rest.len], rest);
            self.tail_len += rest.len;
            return w;
        }

        /// End the message: encrypt the padded tail, or decrypt and unpad the
        /// held block. `out` needs `block_len` octets of room (as EVP's
        /// `Final`); `BufferTooSmall` changes nothing, any other error ends
        /// the message. Returns the octets written (0..`block_len`); the
        /// stream then needs `setIv` before the next one.
        pub fn finish(self: *Self, out: []u8) StreamError!usize {
            if (out.len < block_len) return error.BufferTooSmall;
            defer self.tail_len = 0;
            const n = self.tail_len;
            if (dir == .encrypt) {
                var block: [block_len]u8 = undefined;
                const len = switch (padding) {
                    .none => if (n == 0) 0 else return error.NotBlockAligned,
                    .pkcs7 => padPkcs7(self.tail[0..n], &block) catch unreachable,
                    .ansi_x923 => padAnsiX923(self.tail[0..n], &block) catch unreachable,
                    .iso7816 => padIso7816(self.tail[0..n], &block) catch unreachable,
                    .zero => padZero(self.tail[0..n], &block) catch unreachable,
                };
                _ = try self.inner.update(block[0..len], out[0..len]);
                return len;
            }
            if (padding == .none) {
                if (n != 0) return error.NotBlockAligned;
                return 0;
            }
            if (padding == .zero and n == 0) return 0; // an empty message
            if (n != block_len) return error.InvalidPadding;
            var block: [block_len]u8 = undefined;
            _ = try self.inner.update(&self.tail, &block);
            const len = switch (padding) {
                .none => unreachable,
                .pkcs7 => try unpadPkcs7(&block),
                .ansi_x923 => try unpadAnsiX923(&block),
                .iso7816 => try unpadIso7816(&block),
                .zero => try unpadZero(&block),
            };
            @memcpy(out[0..len], block[0..len]);
            return len;
        }

        pub fn wipe(self: *Self) void {
            std.crypto.secureZero(u8, std.mem.asBytes(self));
        }
    };
}

// ── PKCS#7 padding (RFC 5652 §6.3) ──────────────────────────────────────────
//
// Every pad byte equals the pad length N (1 <= N <= block_len). Always pads,
// even when the message is already block-aligned (a full-block message gains
// one whole pad block) — that is what makes unpadding unambiguous. This is
// the scheme `jwe`'s `A128CBC-HS256`/`A256CBC-HS512` (RFC 7518 §5.2.2.1
// step 2) needs.

/// PKCS#7-padded length for a `msg_len`-byte message. Always adds between 1
/// and `block_len` bytes (never zero).
pub fn paddedLenPkcs7(msg_len: usize) usize {
    return msg_len + (block_len - msg_len % block_len);
}

/// Write `msg` followed by PKCS#7 padding into `out`. `out` must be at least
/// `paddedLenPkcs7(msg.len)` bytes. Returns the padded length.
pub fn padPkcs7(msg: []const u8, out: []u8) error{BufferTooSmall}!usize {
    const padded_len = paddedLenPkcs7(msg.len);
    if (out.len < padded_len) return error.BufferTooSmall;
    @memcpy(out[0..msg.len], msg);
    const pad: u8 = @intCast(padded_len - msg.len);
    @memset(out[msg.len..padded_len], pad);
    return padded_len;
}

/// Strip PKCS#7 padding from a decrypted, block-aligned buffer. Validates
/// `1 <= N <= block_len` AND that all N trailing bytes equal N, accumulating
/// every check into a single flag with no secret-dependent early exit (no
/// distinct control-flow signal for "bad length" vs. "bad pad byte") before
/// returning `InvalidPadding`. Returns the unpadded length on success.
///
/// ⭐ MEASURED, not reviewed (`src/ctgrind_harness.zig`, target `pkcs7`; the
/// row is pinned in `scripts/ctgrind-expected.tsv`). With the whole padded
/// buffer marked undefined, memcheck reports ONE context in this file, at the
/// `if (invalid != 0)` below — the accept/reject decision this function returns
/// to its caller anyway. The scan loop contributes none, so there is no early
/// exit and no per-reason signal, which is what the paragraph above claims.
/// It is measured because the same `@intFromBool`/`u1` idiom did NOT survive
/// the compiler in `fss` (`dpf.zig:326`): written branch-free, lowered to a
/// jump on the secret at one of its three call sites. Reading this code is not
/// evidence about the binary built from it.
pub fn unpadPkcs7(buf: []const u8) PaddingError!usize {
    if (buf.len == 0 or buf.len % block_len != 0) return error.InvalidPadding;
    const n = buf[buf.len - 1];
    var invalid: u1 = @intFromBool(n == 0) | @intFromBool(n > block_len);
    // Clamp so the scan below stays in bounds even for an out-of-range `n`
    // (`invalid` is already latched in that case).
    const pad_len: usize = @min(@as(usize, n), block_len);
    var k: usize = 0;
    while (k < block_len) : (k += 1) {
        const in_pad: u1 = @intFromBool(k < pad_len);
        const mismatch: u1 = @intFromBool(buf[buf.len - 1 - k] != n);
        invalid |= in_pad & mismatch;
    }
    if (invalid != 0) return error.InvalidPadding;
    return buf.len - pad_len;
}

// ── XML-Encryption padding (W3C xmlenc-core-1 §5.2) ─────────────────────────
//
// The FINAL byte N (1 <= N <= block_len) is the pad length; the preceding
// N-1 pad bytes are ARBITRARY — only the length byte is meaningful, unlike
// PKCS#7. This is the scheme `xmlenc`'s AES-CBC content decryption needs.
// There is deliberately no `padXmlEnc`: this module only ever needs to
// *decrypt* XML-Enc (xmlenc is a decryption-only module; see its SPEC.md),
// and an encoder is free to fill the non-final pad bytes with anything,
// including zero — `padPkcs7` already produces a valid XML-Enc padding as a
// special case if a caller ever needs to encrypt one.

/// Strip XML-Encryption padding from a decrypted, block-aligned buffer.
/// Validates only `1 <= N <= block_len` (the non-final pad bytes are
/// unconstrained by the scheme itself, so there is nothing else to check) and
/// returns `InvalidPadding` on an out-of-range length byte. Returns the
/// unpadded length on success.
///
/// Branch-free on `N` itself, matching `unpadPkcs7`'s shape: `N` is the LAST
/// byte of the just-decrypted plaintext, i.e. secret-derived, so a data-
/// dependent early `if (n == 0 or n > block_len)` would branch on that secret
/// byte. The check used to do exactly that; accumulating into `invalid` and
/// branching only once, on a value that no longer varies with `N`'s specific
/// magnitude beyond in/out of range, closes that gap the way `unpadPkcs7`
/// already does. No *additional* leak follows from the old shape beyond what
/// the return value (accept/reject) already reveals — `xmlenc`'s decrypt path
/// has no MAC ahead of this CBC decrypt, so accept/reject is observable
/// either way — but this SPEC previously claimed BOTH helpers were
/// branch-free when only `unpadPkcs7` was; this makes the claim true.
pub fn unpadXmlEnc(buf: []const u8) PaddingError!usize {
    if (buf.len == 0 or buf.len % block_len != 0) return error.InvalidPadding;
    const n = buf[buf.len - 1];
    const invalid: u1 = @intFromBool(n == 0) | @intFromBool(n > block_len);
    const pad_len: usize = @min(@as(usize, n), block_len);
    if (invalid != 0) return error.InvalidPadding;
    return buf.len - pad_len;
}

// ── The other schemes RustCrypto's `block-padding` ships ────────────────────
//
// Same posture as above: every unpad scans the whole last block and folds all
// checks into one flag, branching once on accept/reject. ANSI X9.23, ISO 10126
// and ISO/IEC 7816-4 always pad (1..16 bytes), like PKCS#7; zero padding adds
// nothing to an aligned message and so cannot tell a message's own trailing
// zeros from padding -- use it only where the protocol fixes the length.

/// Padded length for the schemes that always pad (PKCS#7, ANSI X9.23,
/// ISO 10126, ISO/IEC 7816-4): 1..`block_len` bytes more than `msg_len`.
pub const paddedLen = paddedLenPkcs7;

/// ANSI X9.23: zero bytes, then the pad length N as the last byte.
pub fn padAnsiX923(msg: []const u8, out: []u8) error{BufferTooSmall}!usize {
    const padded_len = paddedLen(msg.len);
    if (out.len < padded_len) return error.BufferTooSmall;
    @memcpy(out[0..msg.len], msg);
    @memset(out[msg.len .. padded_len - 1], 0);
    out[padded_len - 1] = @intCast(padded_len - msg.len);
    return padded_len;
}

/// Strip ANSI X9.23 padding: `1 <= N <= block_len` and the N-1 bytes before
/// the length byte all zero.
pub fn unpadAnsiX923(buf: []const u8) PaddingError!usize {
    if (buf.len == 0 or buf.len % block_len != 0) return error.InvalidPadding;
    const n = buf[buf.len - 1];
    var invalid: u1 = @intFromBool(n == 0) | @intFromBool(n > block_len);
    const pad_len: usize = @min(@as(usize, n), block_len);
    var k: usize = 1;
    while (k < block_len) : (k += 1) {
        const in_pad: u1 = @intFromBool(k < pad_len);
        invalid |= in_pad & @intFromBool(buf[buf.len - 1 - k] != 0);
    }
    if (invalid != 0) return error.InvalidPadding;
    return buf.len - pad_len;
}

/// ISO 10126: random bytes from `random`, then the pad length N as the last
/// byte. (ISO withdrew the scheme in 2007; it is here for the protocols that
/// still name it.)
pub fn padIso10126(msg: []const u8, out: []u8, random: std.Random) error{BufferTooSmall}!usize {
    const padded_len = paddedLen(msg.len);
    if (out.len < padded_len) return error.BufferTooSmall;
    @memcpy(out[0..msg.len], msg);
    random.bytes(out[msg.len .. padded_len - 1]);
    out[padded_len - 1] = @intCast(padded_len - msg.len);
    return padded_len;
}

/// Strip ISO 10126 padding: only the length byte is defined, so this is the
/// same check as `unpadXmlEnc` (XML-Encryption's padding is this scheme).
pub const unpadIso10126 = unpadXmlEnc;

/// ISO/IEC 7816-4 (also ISO/IEC 9797-1 method 2): one 0x80 byte, then zeros.
pub fn padIso7816(msg: []const u8, out: []u8) error{BufferTooSmall}!usize {
    const padded_len = paddedLen(msg.len);
    if (out.len < padded_len) return error.BufferTooSmall;
    @memcpy(out[0..msg.len], msg);
    out[msg.len] = 0x80;
    @memset(out[msg.len + 1 .. padded_len], 0);
    return padded_len;
}

/// Strip ISO/IEC 7816-4 padding: the last non-zero byte of the last block must
/// be 0x80. Scans all 16 bytes from the end: `seen` latches at the first
/// non-zero byte, whose position and value decide the result.
pub fn unpadIso7816(buf: []const u8) PaddingError!usize {
    if (buf.len == 0 or buf.len % block_len != 0) return error.InvalidPadding;
    var seen: u1 = 0;
    var invalid: u1 = 0;
    var pad_len: usize = 0;
    var k: usize = 0;
    while (k < block_len) : (k += 1) {
        const b = buf[buf.len - 1 - k];
        const first: u1 = ~seen & @intFromBool(b != 0);
        invalid |= first & @intFromBool(b != 0x80);
        // Branch-free select of k + 1 at the first non-zero byte.
        pad_len |= (k + 1) & (@as(usize, 0) -% @as(usize, first));
        seen |= first;
    }
    invalid |= ~seen;
    if (invalid != 0) return error.InvalidPadding;
    return buf.len - pad_len;
}

/// Zero padding: zeros up to the next block boundary, nothing when `msg` is
/// already aligned (RustCrypto `ZeroPadding`).
pub fn paddedLenZero(msg_len: usize) usize {
    return std.mem.alignForward(usize, msg_len, block_len);
}

pub fn padZero(msg: []const u8, out: []u8) error{BufferTooSmall}!usize {
    const padded_len = paddedLenZero(msg.len);
    if (out.len < padded_len) return error.BufferTooSmall;
    @memcpy(out[0..msg.len], msg);
    @memset(out[msg.len..padded_len], 0);
    return padded_len;
}

/// Strip zero padding: drops the trailing zero bytes of the last block (a
/// message ending in zeros loses them -- the scheme cannot tell). Never fails
/// on a block-aligned buffer; `InvalidPadding` only for an unaligned one.
pub fn unpadZero(buf: []const u8) PaddingError!usize {
    if (buf.len % block_len != 0) return error.InvalidPadding;
    if (buf.len == 0) return 0;
    var seen: u1 = 0;
    var pad_len: usize = 0;
    var k: usize = 0;
    while (k < block_len) : (k += 1) {
        seen |= @intFromBool(buf[buf.len - 1 - k] != 0);
        pad_len += ~seen;
    }
    return buf.len - pad_len;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
/// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;
/// Test-only (`test_deps`): the API takes any std-shaped AES type.
const Aes192 = @import("aes192").Aes192;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// NIST SP800-38A Appendix F.2.1 — CBC-AES128.Encrypt/Decrypt.
const f_2_1_key = hex("2b7e151628aed2a6abf7158809cf4f3c");
const f_2_1_iv = hex("000102030405060708090a0b0c0d0e0f");
const f_2_1_plaintext = hex("6bc1bee22e409f96e93d7e117393172a" ++
    "ae2d8a571e03ac9c9eb76fac45af8e51" ++
    "30c81c46a35ce411e5fbc1191a0a52ef" ++
    "f69f2445df4f9b17ad2b417be66c3710");
const f_2_1_ciphertext = hex("7649abac8119b246cee98e9b12e9197d" ++
    "5086cb9b507219ee95db113a917678b2" ++
    "73bed6b8e3c1743b7116e69e22229516" ++
    "3ff1caa1681fac09120eca307586e1a7");

// NIST SP800-38A Appendix F.2.3/F.2.4 — CBC-AES192.Encrypt/Decrypt (re-checked
// against OpenSSL 3 `aes-192-cbc` when added, 2026-10-10).
const f_2_3_key = hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
const f_2_3_ciphertext = hex("4f021db243bc633d7178183a9fa071e8" ++
    "b4d9ada9ad7dedf4e5e738763f69145a" ++
    "571b242012fb7ae07fa9baac3df102e0" ++
    "08b0e27988598881d920a9e64f5615cd");

// NIST SP800-38A Appendix F.2.5 — CBC-AES256.Encrypt/Decrypt (also
// transcribed in ctap2pin/src/kat_vectors.zig and xmlenc/src/root.zig).
const f_2_5_key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
const f_2_5_iv = f_2_1_iv;
const f_2_5_plaintext = f_2_1_plaintext;
const f_2_5_ciphertext = hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6" ++
    "9cfc4e967edb808d679f777bc6702c7d" ++
    "39f23369a9d9bacfa530e26304231461" ++
    "b2eb05e2c39be9fcda6c19078c6a9d1b");

test "NIST SP800-38A F.2.1 (AES-128-CBC): byte-exact encrypt" {
    var out: [f_2_1_plaintext.len]u8 = undefined;
    const n = try encrypt(Aes128, &f_2_1_key, f_2_1_iv, &f_2_1_plaintext, &out);
    try testing.expectEqualSlices(u8, &f_2_1_ciphertext, out[0..n]);
}

test "NIST SP800-38A F.2.1 (AES-128-CBC): byte-exact decrypt" {
    var out: [f_2_1_ciphertext.len]u8 = undefined;
    const n = try decrypt(Aes128, &f_2_1_key, f_2_1_iv, &f_2_1_ciphertext, &out);
    try testing.expectEqualSlices(u8, &f_2_1_plaintext, out[0..n]);
}

test "NIST SP800-38A F.2.3 (AES-192-CBC): byte-exact encrypt" {
    var out: [64]u8 = undefined;
    const n = try encrypt(Aes192, &f_2_3_key, f_2_1_iv, &f_2_1_plaintext, &out);
    try testing.expectEqualSlices(u8, &f_2_3_ciphertext, out[0..n]);
}

test "NIST SP800-38A F.2.4 (AES-192-CBC): byte-exact decrypt" {
    var out: [64]u8 = undefined;
    const n = try decrypt(Aes192, &f_2_3_key, f_2_1_iv, &f_2_3_ciphertext, &out);
    try testing.expectEqualSlices(u8, &f_2_1_plaintext, out[0..n]);
}

test "NIST SP800-38A F.2.5 (AES-256-CBC): byte-exact encrypt" {
    var out: [f_2_5_plaintext.len]u8 = undefined;
    const n = try encrypt(Aes256, &f_2_5_key, f_2_5_iv, &f_2_5_plaintext, &out);
    try testing.expectEqualSlices(u8, &f_2_5_ciphertext, out[0..n]);
}

test "NIST SP800-38A F.2.5 (AES-256-CBC): byte-exact decrypt" {
    var out: [f_2_5_ciphertext.len]u8 = undefined;
    const n = try decrypt(Aes256, &f_2_5_key, f_2_5_iv, &f_2_5_ciphertext, &out);
    try testing.expectEqualSlices(u8, &f_2_5_plaintext, out[0..n]);
}

test "raw CBC rejects non-block-aligned input" {
    var out: [32]u8 = undefined;
    try testing.expectError(error.NotBlockAligned, encrypt(Aes128, &f_2_1_key, f_2_1_iv, "not sixteen", &out));
    try testing.expectError(error.NotBlockAligned, decrypt(Aes128, &f_2_1_key, f_2_1_iv, "not sixteen", &out));
}

test "raw CBC rejects an undersized out buffer" {
    var out: [16]u8 = undefined; // plaintext is 2 blocks, out is 1
    const pt = [_]u8{0x41} ** 32;
    try testing.expectError(error.BufferTooSmall, encrypt(Aes128, &f_2_1_key, f_2_1_iv, &pt, &out));
}

test "raw CBC decrypt rejects an undersized out buffer" {
    var out: [16]u8 = undefined; // ciphertext is 2 blocks, out is 1
    const ct = [_]u8{0x41} ** 32;
    try testing.expectError(error.BufferTooSmall, decrypt(Aes128, &f_2_1_key, f_2_1_iv, &ct, &out));
}

test "raw CBC round-trip: empty message" {
    var out: [0]u8 = undefined;
    const n = try encrypt(Aes128, &f_2_1_key, f_2_1_iv, "", &out);
    try testing.expectEqual(@as(usize, 0), n);
    const m = try decrypt(Aes128, &f_2_1_key, f_2_1_iv, "", &out);
    try testing.expectEqual(@as(usize, 0), m);
}

test "raw CBC round-trip: multi-block message, self-consistency" {
    const key = [_]u8{0x5a} ** 32;
    const iv = [_]u8{0x11} ** block_len;
    // Four AES blocks (64 bytes) of distinguishable, non-repeating content.
    var pt: [64]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = @truncate(i);

    var ct: [pt.len]u8 = undefined;
    _ = try encrypt(Aes256, &key, iv, &pt, &ct);
    var recovered: [pt.len]u8 = undefined;
    const n = try decrypt(Aes256, &key, iv, &ct, &recovered);
    try testing.expectEqualSlices(u8, &pt, recovered[0..n]);
}

// ── PKCS#7 tests ─────────────────────────────────────────────────────────────

test "PKCS#7 pad/unpad round-trip: not block-aligned" {
    const msg = "seventeen bytes!!"; // 17 bytes -> one full block + 1 pad block
    var padded: [32]u8 = undefined;
    const n = try padPkcs7(msg, &padded);
    try testing.expectEqual(@as(usize, 32), n);
    try testing.expectEqual(@as(usize, 32), paddedLenPkcs7(msg.len));
    // Trailing 15 bytes are all 0x0f (pad length 15).
    for (padded[17..32]) |b| try testing.expectEqual(@as(u8, 15), b);

    const m = try unpadPkcs7(padded[0..n]);
    try testing.expectEqualStrings(msg, padded[0..m]);
}

test "PKCS#7 pad/unpad round-trip: exactly block-aligned still gains a full pad block" {
    const msg = [_]u8{0x42} ** 16;
    var padded: [32]u8 = undefined;
    const n = try padPkcs7(&msg, &padded);
    try testing.expectEqual(@as(usize, 32), n);
    for (padded[16..32]) |b| try testing.expectEqual(@as(u8, 16), b);

    const m = try unpadPkcs7(padded[0..n]);
    try testing.expectEqualSlices(u8, &msg, padded[0..m]);
}

test "PKCS#7 pad/unpad round-trip through real CBC encrypt/decrypt" {
    const key = [_]u8{0x33} ** 16;
    const iv = [_]u8{0x44} ** block_len;
    const msg = "A message that is not a multiple of the block size.";

    var padded: [128]u8 = undefined;
    const padded_len = try padPkcs7(msg, &padded);

    var ct: [128]u8 = undefined;
    _ = try encrypt(Aes128, &key, iv, padded[0..padded_len], ct[0..padded_len]);

    var pt: [128]u8 = undefined;
    _ = try decrypt(Aes128, &key, iv, ct[0..padded_len], pt[0..padded_len]);
    const n = try unpadPkcs7(pt[0..padded_len]);
    try testing.expectEqualStrings(msg, pt[0..n]);
}

test "PKCS#7 unpad rejects: zero-length pad byte (0x00)" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x00;
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&buf));
}

test "PKCS#7 unpad rejects: pad length > block_len" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x11; // 17 > 16
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&buf));
}

// Mutation run 2026-10-05: the test above also fails the byte comparison
// (only the last octet is 0x11), so the `n > block_len` check itself was
// unpinned — relaxed to `n > 17`, a whole block of 0x11 unpadded to
// `len - 16`. RFC 5652 §6.3: the pad length is 1..block_len.
test "PKCS#7 unpad rejects: a whole block of 0x11 (pad 17, every byte consistent)" {
    const buf = [_]u8{0x41} ** block_len ++ [_]u8{0x11} ** block_len;
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&buf));
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&buf));
}

test "PKCS#7 unpad rejects: inconsistent pad bytes" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x04; // claims last 4 bytes == 0x04
    buf[block_len - 2] = 0x04;
    buf[block_len - 3] = 0x04;
    buf[block_len - 4] = 0x99; // ...but this one doesn't match
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&buf));
}

test "PKCS#7 unpad rejects: empty or non-block-aligned buffer" {
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&[_]u8{}));
    try testing.expectError(error.InvalidPadding, unpadPkcs7(&[_]u8{ 1, 2, 3 }));
}

test "PKCS#7 unpad accepts: pad length == block_len with a full pad block, empty-ish message" {
    const buf = [_]u8{0x10} ** block_len; // valid: N=16, all 16 bytes == 16
    const n = try unpadPkcs7(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

// ── XML-Enc padding tests ────────────────────────────────────────────────────

test "XML-Enc unpad accepts a valid pad with arbitrary non-final pad bytes" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x04; // N=4
    buf[block_len - 2] = 0xAA; // arbitrary, NOT required to equal N
    buf[block_len - 3] = 0x00; // arbitrary
    buf[block_len - 4] = 0xFF; // arbitrary
    const n = try unpadXmlEnc(&buf);
    try testing.expectEqual(@as(usize, block_len - 4), n);
}

test "XML-Enc unpad accepts: pad length == block_len with a full pad block, empty-ish message" {
    const buf = [_]u8{0x10} ** block_len; // valid: N=16, all 16 bytes are pad
    const n = try unpadXmlEnc(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "XML-Enc unpad rejects: zero-length pad byte" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0x00;
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&buf));
}

test "XML-Enc unpad rejects: pad length > block_len" {
    var buf = [_]u8{0x41} ** block_len;
    buf[block_len - 1] = 0xFF;
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&buf));
}

test "XML-Enc unpad rejects: empty or non-block-aligned buffer" {
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&[_]u8{}));
    try testing.expectError(error.InvalidPadding, unpadXmlEnc(&[_]u8{ 1, 2, 3, 4 }));
}

test "XML-Enc unpad round-trip through real CBC encrypt/decrypt" {
    const key = [_]u8{0x77} ** 32;
    const iv = [_]u8{0x88} ** block_len;
    const msg = "recovered plaintext";
    // xmlenc-style pad: last byte = N, preceding N-1 bytes arbitrary (use
    // PKCS#7's own construction here as one valid instance of the scheme).
    var padded: [64]u8 = undefined;
    const padded_len = try padPkcs7(msg, &padded);

    var ct: [64]u8 = undefined;
    _ = try encrypt(Aes256, &key, iv, padded[0..padded_len], ct[0..padded_len]);
    var pt: [64]u8 = undefined;
    _ = try decrypt(Aes256, &key, iv, ct[0..padded_len], pt[0..padded_len]);
    const n = try unpadXmlEnc(pt[0..padded_len]);
    try testing.expectEqualStrings(msg, pt[0..n]);
}

// ── fuzz: the unpad guards, on arbitrary decrypted-buffer content ──────────
//
// W2 A3 (F2): CLASS B, zero `testing.fuzz(` harnesses — this module was
// absent from `scripts/fuzz-sweep.sh`'s target list entirely. Per the
// campaign brief, `encrypt`/`decrypt`'s AES-CBC core is a crypto primitive
// already pinned byte-exact against NIST SP800-38A above; fuzzing it again
// would duplicate the KATs, not add to them. The genuinely untested-by-fuzz
// surface is the framing/parsing logic in `unpadPkcs7`/`unpadXmlEnc`: both
// consume a buffer that, on a chosen-ciphertext path, is attacker-shaped
// (the audit's own framing — F2's evidence column).
//
// Oracle: not "never panics" alone. Success from either function is a
// specific, checkable claim about the buffer's *last byte* and (for PKCS#7)
// every byte in the claimed pad — so the harness asserts that claim holds,
// which is strictly stronger than surviving without a crash.
// ⚠ Both halves of this harness were dead until 2026-09-07. It opened with
//
//     const len = smith.valueRangeAtMost(u16, 0, buf.len);
//     smith.bytes(buf[0..len]);
//
// and carried no corpus. A ranged draw reads eight octets as a little-endian
// u64 and returns the range MINIMUM when fewer than eight remain, so `len` was
// 0 on every input — and the comment that used to sit here, "length drawn first
// so every mutated byte lands inside `data`", described a `data` that was
// always empty. `unpadPkcs7("")`/`unpadXmlEnc("")` both return `InvalidPadding`
// at the first line, so NEITHER of the two invariant blocks below had ever
// executed a single assertion.
//
// The fix is one byte-first draw (`smith.slice`) plus a corpus: a random
// 16-octet buffer ends in a pad byte in `1..16` about 6% of the time, so
// arbitrary bytes do reach the success path eventually, but not in the one
// input the ordinary lane runs. The seeds below pin both accepting shapes and
// the four distinct refusals.
const unpad_seeds = [_][]const u8{
    // PKCS#7-valid, one block: 11 octets of message + 5 × 0x05.
    testkit.fuzz.seedHex("6161616161616161616161" ++ "0505050505"),
    // PKCS#7-valid, two blocks, a full block of padding (N = 16).
    testkit.fuzz.seedHex("00112233445566778899aabbccddeeff" ++ ("10" ** 16)),
    // PKCS#7-valid with N = 1: the shortest pad the scheme allows.
    testkit.fuzz.seedHex("000102030405060708090a0b0c0d0e" ++ "01"),
    // ⭐ The scheme split: last byte 0x10 but the preceding 15 are not, so
    // PKCS#7 refuses and XML-Enc — which only reads the LENGTH byte — accepts
    // and returns 0. The one seed that tells the two functions apart.
    testkit.fuzz.seedHex(("a5" ** 15) ++ "10"),
    // N = 0: refused by both, and the reason `unpadPkcs7` latches a flag
    // instead of returning early.
    testkit.fuzz.seedHex(("a5" ** 15) ++ "00"),
    // N = 17 > block_len: refused by both, and the input that would run the
    // `@min` clamp off the end of the buffer if it were not clamped.
    testkit.fuzz.seedHex(("a5" ** 15) ++ "11"),
    // 20 octets: not block-aligned, refused before the last byte is read.
    testkit.fuzz.seedHex("00112233445566778899aabbccddeeff" ++ "05050505"),
    // The input this target ran, and only ran, for ever.
    testkit.fuzz.seed(""),
};

test "fuzz: unpad functions never panic, and a successful unpad's invariant actually holds" {
    try testing.fuzz({}, fuzzUnpad, .{ .corpus = &unpad_seeds });
}

fn fuzzUnpad(_: void, smith: *testing.Smith) !void {
    // One byte-first draw: the length is the seed's own, not a collapsing
    // ranged draw taken before it.
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const data = buf[0..len];

    if (unpadPkcs7(data)) |n| {
        try testing.expect(data.len > 0 and data.len % block_len == 0);
        const pad = data[data.len - 1];
        try testing.expect(pad >= 1 and pad <= block_len);
        try testing.expectEqual(data.len - @as(usize, pad), n);
        for (data[n..]) |b| try testing.expectEqual(pad, b);
    } else |_| {}

    if (unpadXmlEnc(data)) |n| {
        try testing.expect(data.len > 0 and data.len % block_len == 0);
        const pad = data[data.len - 1];
        try testing.expect(pad >= 1 and pad <= block_len);
        try testing.expectEqual(data.len - @as(usize, pad), n);
    } else |_| {}
}

test "corpus: every unpad seed reaches the guards, counts pinned" {
    var nonempty: usize = 0;
    var pkcs7_ok: usize = 0;
    var xmlenc_ok: usize = 0;
    // ⛔ A count of successes alone would not notice a corpus that collapsed to
    // one seed. `pkcs7_octets` is the number the empty input cannot make: it
    // only moves when a seed's OWN length and pad byte were both read.
    var pkcs7_octets: usize = 0;
    for (unpad_seeds) |sd| {
        var smith: testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (unpadPkcs7(buf[0..len])) |n| {
            pkcs7_ok += 1;
            pkcs7_octets += n;
        } else |_| {}
        if (unpadXmlEnc(buf[0..len])) |_| {
            xmlenc_ok += 1;
        } else |_| {}
    }
    try testing.expectEqual(unpad_seeds.len - 1, nonempty); // the last seed is empty
    try testing.expectEqual(@as(usize, 3), pkcs7_ok);
    // One more than PKCS#7: the "length byte only" seed, which is the whole
    // difference between the two schemes.
    try testing.expectEqual(@as(usize, 4), xmlenc_ok);
    try testing.expectEqual(@as(usize, 42), pkcs7_octets); // 11 + 16 + 15
}

test "raw CBC vs jwe's/xmlenc's hand-rolled shape: same output on the same input" {
    // Sanity oracle: reproduce the loop shape from jwe/src/enc.zig and
    // xmlenc/src/root.zig using ONLY std.crypto (not this module's own
    // encrypt/decrypt) and confirm they agree with the module.
    const key = [_]u8{0x21} ** 16;
    const iv = [_]u8{0x22} ** block_len;
    const pt = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 } ** 2;

    var expected: [pt.len]u8 = undefined;
    {
        const ctx = Aes128.initEnc(key);
        var prev: [block_len]u8 = iv;
        var i: usize = 0;
        while (i < pt.len) : (i += block_len) {
            var block: [block_len]u8 = pt[i..][0..block_len].*;
            for (&block, prev) |*b, p| b.* ^= p;
            ctx.encrypt(&block, &block);
            @memcpy(expected[i..][0..block_len], &block);
            prev = block;
        }
    }

    var out: [pt.len]u8 = undefined;
    _ = try encrypt(Aes128, &key, iv, &pt, &out);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "Encryptor/Decryptor: SP800-38A F.2.1/F.2.3/F.2.5 fed one block at a time" {
    inline for (.{
        .{ Aes128, &f_2_1_key, &f_2_1_ciphertext },
        .{ Aes192, &f_2_3_key, &f_2_3_ciphertext },
        .{ Aes256, &f_2_5_key, &f_2_5_ciphertext },
    }) |c| {
        var e = Encryptor(c[0]).init(c[1], f_2_1_iv);
        var d = Decryptor(c[0]).init(c[1], f_2_1_iv);
        var ct: [64]u8 = undefined;
        var pt: [64]u8 = undefined;
        var i: usize = 0;
        while (i < 64) : (i += 16) {
            _ = try e.update(f_2_1_plaintext[i..][0..16], ct[i..][0..16]);
            _ = try d.update(c[2][i..][0..16], pt[i..][0..16]);
        }
        try testing.expectEqualSlices(u8, c[2], &ct);
        try testing.expectEqualSlices(u8, &f_2_1_plaintext, &pt);
        // setIv starts the next message: the same bytes again, in one call,
        // in place.
        e.setIv(f_2_1_iv);
        var buf = f_2_1_plaintext;
        _ = try e.update(&buf, &buf);
        try testing.expectEqualSlices(u8, c[2], &buf);
        d.setIv(f_2_1_iv);
        _ = try d.update(&buf, &buf);
        try testing.expectEqualSlices(u8, &f_2_1_plaintext, &buf);
        e.wipe();
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&e), 0));
    }
}

test "decrypt: a message longer than one decryptWide group, in place, against the encrypt" {
    var msg: [16 * (2 * wide + 3)]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 7 +% 1);
    var buf = msg;
    _ = try encrypt(Aes256, &f_2_5_key, f_2_1_iv, &buf, &buf);
    var d = Decryptor(Aes256).init(&f_2_5_key, f_2_1_iv);
    // One group, then the rest: the chain crosses a group boundary between calls.
    _ = try d.update(buf[0 .. 16 * wide], buf[0 .. 16 * wide]);
    _ = try d.update(buf[16 * wide ..], buf[16 * wide ..]);
    try testing.expectEqualSlices(u8, &msg, &buf);
}

// RFC 3962 Appendix B (Kerberos AES-CTS = CS3): AES-128, key "chicken
// teriyaki", IV 0, prefixes of one sentence. CS1 is OpenSSL 3.5.5's
// `openssl enc -aes-128-cbc-cts -nopad` (its default `cts_mode`), 2026-10-16.
const cts_key = "chicken teriyaki".*;
const cts_msg = "I would like the General Gau's Chicken, please, and wonton soup.";
const cts_vectors = blk: {
    @setEvalBranchQuota(20_000);
    break :blk [_]struct { len: usize, cs3: []const u8, cs1: []const u8 }{
        .{ .len = 17, .cs3 = &hex("c6353568f2bf8cb4d8a580362da7ff7f97"), .cs1 = &hex("97c6353568f2bf8cb4d8a580362da7ff7f") },
        .{ .len = 31, .cs3 = &hex("fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"), .cs1 = &hex("97687268d6ecccc0c07b25e25ecfe5fc00783e0efdb2c1d445d4c8eff7ed22") },
        .{ .len = 32, .cs3 = &hex("39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"), .cs1 = &hex("97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8") },
        .{ .len = 47, .cs3 = &hex("97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5"), .cs1 = &hex("97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5b3fffd940c16a18c1b5549d2f838029e") },
        .{ .len = 48, .cs3 = &hex("97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8"), .cs1 = &hex("97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a89dad8bbb96c4cdc03bc103e1a194bbd8") },
        .{ .len = 64, .cs3 = &hex("97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8"), .cs1 = &hex("97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a89dad8bbb96c4cdc03bc103e1a194bbd84807efe836ee89a526730dbc2f7bc840") },
    };
};

test "CTS: RFC 3962 (CS3) and OpenSSL (CS1) vectors, CS2 between them, both directions, in place" {
    const zero_iv: [16]u8 = @splat(0);
    for (cts_vectors) |v| {
        const d = v.len - (v.len - 1) / 16 * 16;
        var out: [64]u8 = undefined;
        inline for (.{ CtsVariant.cs1, CtsVariant.cs2, CtsVariant.cs3 }) |variant| {
            const want = switch (variant) {
                .cs1 => v.cs1,
                .cs2 => if (d == 16) v.cs1 else v.cs3,
                .cs3 => v.cs3,
            };
            try testing.expectEqual(v.len, try encryptCts(Aes128, variant, &cts_key, zero_iv, cts_msg[0..v.len], &out));
            try testing.expectEqualSlices(u8, want, out[0..v.len]);
            var buf: [64]u8 = undefined;
            @memcpy(buf[0..v.len], want);
            _ = try decryptCts(Aes128, variant, &cts_key, zero_iv, buf[0..v.len], buf[0..v.len]);
            try testing.expectEqualSlices(u8, cts_msg[0..v.len], buf[0..v.len]);
            @memcpy(buf[0..v.len], cts_msg[0..v.len]);
            _ = try encryptCts(Aes128, variant, &cts_key, zero_iv, buf[0..v.len], buf[0..v.len]);
            try testing.expectEqualSlices(u8, want, buf[0..v.len]);
        }
    }
    var out: [16]u8 = undefined;
    try testing.expectError(error.TooShort, encryptCts(Aes128, .cs3, &cts_key, zero_iv, cts_msg[0..15], &out));
    try testing.expectError(error.TooShort, decryptCts(Aes128, .cs1, &cts_key, zero_iv, "", &out));
    try testing.expectError(error.BufferTooSmall, encryptCts(Aes128, .cs1, &cts_key, zero_iv, cts_msg[0..17], &out));
    // One block: plain CBC in every variant.
    _ = try encryptCts(Aes128, .cs3, &cts_key, zero_iv, cts_msg[0..16], &out);
    var cbc: [16]u8 = undefined;
    _ = try encrypt(Aes128, &cts_key, zero_iv, cts_msg[0..16], &cbc);
    try testing.expectEqualSlices(u8, &cbc, &out);
}

test "ANSI X9.23: pad layout, round trip, refusals" {
    var out: [32]u8 = undefined;
    const n = try padAnsiX923("YELLOW SUBMARINE!", &out);
    try testing.expectEqual(@as(usize, 32), n);
    try testing.expectEqualSlices(u8, &(.{0} ** 14 ++ .{15}), out[17..32]);
    try testing.expectEqual(@as(usize, 17), try unpadAnsiX923(out[0..n]));
    out[20] = 1; // a non-zero filler byte
    try testing.expectError(error.InvalidPadding, unpadAnsiX923(out[0..n]));
    var full: [16]u8 = .{0} ** 15 ++ .{16};
    try testing.expectEqual(@as(usize, 0), try unpadAnsiX923(&full));
    full[15] = 17;
    try testing.expectError(error.InvalidPadding, unpadAnsiX923(&full));
    full[15] = 0;
    try testing.expectError(error.InvalidPadding, unpadAnsiX923(&full));
}

test "ISO/IEC 7816-4: pad layout, round trip, refusals" {
    var out: [32]u8 = undefined;
    const n = try padIso7816("0123456789abcdef", &out);
    try testing.expectEqual(@as(usize, 32), n);
    try testing.expectEqualSlices(u8, &(.{0x80} ++ .{0} ** 15), out[16..32]);
    try testing.expectEqual(@as(usize, 16), try unpadIso7816(out[0..n]));
    var blk: [16]u8 = "abcdefghijklmno\x80".*;
    try testing.expectEqual(@as(usize, 15), try unpadIso7816(&blk));
    blk[15] = 0x81;
    try testing.expectError(error.InvalidPadding, unpadIso7816(&blk));
    blk = .{0} ** 16;
    try testing.expectError(error.InvalidPadding, unpadIso7816(&blk)); // no marker
    blk[3] = 0x80;
    try testing.expectEqual(@as(usize, 3), try unpadIso7816(&blk));
    blk[9] = 0x80; // the LAST non-zero byte decides
    try testing.expectEqual(@as(usize, 9), try unpadIso7816(&blk));
}

test "ISO 10126 and zero padding" {
    var prng = std.Random.DefaultPrng.init(1);
    var out: [32]u8 = undefined;
    const n = try padIso10126("abc", &out, prng.random());
    try testing.expectEqual(@as(usize, 16), n);
    try testing.expectEqual(@as(u8, 13), out[15]);
    try testing.expectEqual(@as(usize, 3), try unpadIso10126(out[0..n]));

    try testing.expectEqual(@as(usize, 16), try padZero("abc", &out));
    try testing.expectEqualSlices(u8, &(.{0} ** 13), out[3..16]);
    try testing.expectEqual(@as(usize, 3), try unpadZero(out[0..16]));
    // Aligned: nothing added.
    try testing.expectEqual(@as(usize, 16), try padZero("0123456789abcdef", &out));
    try testing.expectEqual(@as(usize, 16), try unpadZero(out[0..16]));
    try testing.expectEqual(@as(usize, 0), try unpadZero(""));
    try testing.expectError(error.InvalidPadding, unpadZero(out[0..15]));
}

test {
    _ = @import("stackprobe_test.zig");
    _ = @import("fuzz_test.zig");
}
