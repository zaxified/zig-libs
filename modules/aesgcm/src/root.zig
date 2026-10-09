// SPDX-License-Identifier: MIT

//! aesgcm — AES-GCM (NIST SP 800-38D), AES-128 and AES-256, 96-bit nonces,
//! 128-bit tags: a drop-in for `std.crypto.aead.aes_gcm` plus a stateful
//! `Context` that keeps the expanded key and the GHASH key powers across
//! messages.
//!
//! Two things make it faster than std's:
//!
//! - **One pass.** On x86-64 with AES-NI and PCLMULQDQ, eight counter blocks
//!   go through the AES rounds while the eight ciphertext blocks before them
//!   are multiplied into GHASH (aggregated reduction: one reduction per eight
//!   blocks), so the AES unit and the carry-less multiplier work at the same
//!   time. std runs CTR over the whole message and then GHASH over the whole
//!   ciphertext.
//! - **No per-message setup** with a `Context`: std's AEAD is stateless, so
//!   every call expands the key, encrypts the zero block for H and computes
//!   H's powers again. A TLS connection pays that per record.
//!
//! The backend is chosen once: at compile time when the build target
//! guarantees AES-NI, PCLMULQDQ and SSSE3, else by CPUID on first use (Zig
//! 0.16 has no per-function target features, so the instructions are inline
//! assembly, which does not need them). Everywhere else — arm64 included —
//! the `generic` backend runs std's own AES and GHASH primitives (hardware on
//! arm64 when the target has `aes`), still with the per-key state cached.

const std = @import("std");
const burn = @import("burn.zig");
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;
const assert = std.debug.assert;
const Ghash = crypto.onetimeauth.Ghash;

pub const meta = .{
    .doc = "AES-GCM (AES-128/256) — stateful context caching the key schedule and GHASH powers, x86-64 AES-NI+PCLMULQDQ stitched one-pass kernel picked at run time, std fallback; std-shaped stateless API.",
    .platform_note = "any (x86-64 AES-NI/PCLMULQDQ asm, run-time detected + std fallback)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "OpenSSL/BoringSSL aesni-gcm (stitched CTR+GHASH); Gueron–Kounavis Intel CLMUL GCM white paper; std.crypto.aead.aes_gcm API",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

pub const AuthenticationError = crypto.errors.AuthenticationError;

pub const Aes128Gcm = AesGcm(128);
pub const Aes256Gcm = AesGcm(256);

pub const Backend = enum {
    /// std's `crypto.core.aes` block cipher, `modes.ctr` and `Ghash`, with
    /// the key schedule and GHASH key cached. Any CPU; hardware AES and
    /// PMULL on arm64 when the build target has `aes`.
    generic,
    /// x86-64 AES-NI + PCLMULQDQ (+ SSSE3 `pshufb`): the stitched kernel.
    aesni,
};

/// The backend `init` and the stateless functions use on this CPU.
pub fn backend() Backend {
    if (comptime staticBackend()) |b| return b;
    const cached = detected.load(.monotonic);
    if (cached != 0) return @enumFromInt(cached - 1);
    const b = detect();
    detected.store(@as(u8, @intFromEnum(b)) + 1, .monotonic);
    return b;
}

/// Whether `b` runs on this CPU. `.generic` always does.
pub fn available(b: Backend) bool {
    return switch (b) {
        .generic => true,
        .aesni => x86_asm and ((comptime staticBackend() == .aesni) or cpuidAesni()),
    };
}

/// AES-GCM over a `key_bits`-bit key: 96-bit nonce, 128-bit tag.
fn AesGcm(comptime key_bits: u16) type {
    comptime assert(key_bits == 128 or key_bits == 256);
    return struct {
        pub const key_length = key_bits / 8;
        pub const nonce_length = 12;
        pub const tag_length = 16;

        const nr = if (key_bits == 128) 10 else 14;
        const StdGcm = if (key_bits == 128) crypto.aead.aes_gcm.Aes128Gcm else crypto.aead.aes_gcm.Aes256Gcm;
        const StdAes = if (key_bits == 128) crypto.core.aes.Aes128 else crypto.core.aes.Aes256;
        const Ni = NiKey(key_bits);

        /// Everything derived from one key: the AES round keys and the GHASH
        /// key H with its powers. Build it once per key and use it for any
        /// number of messages; it is never written after `init`, so one
        /// `Context` may be shared by threads.
        ///
        /// It holds secrets. Call `wipe` when the key is retired — nothing
        /// else clears it (`CONVENTIONS.md` §2.1: the module cannot know when
        /// the caller is done with it).
        ///
        /// Dead stack (`CONVENTIONS.md` §2.1.1): `init*` burn (key expansion),
        /// the per-message `Context.encrypt`/`decrypt` deliberately do NOT — a
        /// keyed transform's working state is §2.1's Z3, and the burn belongs
        /// to the protocol entry point that owns the key and the message
        /// (dtls/quic-crypto `protect`, oscore, hpke, aeadframe), which runs
        /// this call inside its own burn. Burning here too would pay twice per
        /// record (decision 2026-10-09).
        pub const Context = struct {
            impl: union(Backend) {
                generic: Generic,
                aesni: Ni,
            },

            /// The context for `key` on the fastest backend this CPU has.
            /// `initInto` is the dead-stack-clean form: no key copy in the
            /// caller's frame, no `Context` in its result slot.
            pub fn init(key: [key_length]u8) Context {
                return burn.run(burn.msg_burn, Context, initBody, .{&key});
            }

            /// `out` ← the context for `*key` on the fastest backend (the
            /// pointer twin of `init`).
            pub fn initInto(out: *Context, key: *const [key_length]u8) void {
                burn.run(burn.msg_burn, void, initIntoBody, .{ out, key });
            }

            fn initBody(key: *const [key_length]u8) Context {
                return initWithBody(backend(), key).?;
            }

            fn initIntoBody(out: *Context, key: *const [key_length]u8) void {
                out.* = initWithBody(backend(), key).?;
            }

            /// The context for `key` on backend `b`, or null when this CPU
            /// lacks it — for tests and measurements that compare backends.
            pub fn initWith(b: Backend, key: [key_length]u8) ?Context {
                return burn.run(burn.msg_burn, ?Context, initWithBody, .{ b, &key });
            }

            /// `out` ← the context for `*key` on backend `b`; false (and
            /// `out` untouched) when this CPU lacks it. The pointer twin of
            /// `initWith`.
            pub fn initWithInto(out: *Context, b: Backend, key: *const [key_length]u8) bool {
                return burn.run(burn.msg_burn, bool, initWithIntoBody, .{ out, b, key });
            }

            fn initWithIntoBody(out: *Context, b: Backend, key: *const [key_length]u8) bool {
                out.* = initWithBody(b, key) orelse return false;
                return true;
            }

            fn initWithBody(b: Backend, key: *const [key_length]u8) ?Context {
                if (!available(b)) return null;
                return switch (b) {
                    .generic => .{ .impl = .{ .generic = .init(key.*) } },
                    .aesni => if (x86_asm) .{ .impl = .{ .aesni = .init(key.*, 8) } } else unreachable,
                };
            }

            /// `c` ← AES-GCM encryption of `m`, `tag` ← its tag over `ad`
            /// and `c`. Asserts `c.len == m.len` and `m.len ≤ 2^36 − 32`.
            /// `c` may be `m` itself (in place), or start before it inside
            /// the same buffer (`c.ptr < m.ptr`); it must not start after
            /// it and overlap.
            pub fn encrypt(ctx: *const Context, c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) void {
                assert(c.len == m.len);
                assert(m.len <= max_message_len);
                switch (ctx.impl) {
                    .generic => |*g| g.seal(c, tag, m, ad, npub),
                    .aesni => |*k| if (x86_asm) k.seal(c, tag, m, ad, npub) else unreachable,
                }
            }

            /// `m` ← decryption of `c` if `tag` authenticates `ad` and `c`
            /// under this key and `npub`; else `error.AuthenticationFailed`
            /// with every byte of `m` zeroed. Asserts `c.len == m.len`. `m`
            /// may be `c` itself (in place) or start before it inside the
            /// same buffer — a record decrypted over its own header; on
            /// failure the overlapped ciphertext is gone too.
            pub fn decrypt(ctx: *const Context, m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8) AuthenticationError!void {
                assert(c.len == m.len);
                assert(m.len <= max_message_len);
                switch (ctx.impl) {
                    .generic => |*g| return g.open(m, c, tag, ad, npub),
                    .aesni => |*k| if (x86_asm) return k.open(m, c, tag, ad, npub) else unreachable,
                }
            }

            /// Zero every byte of the context (round keys, H and its
            /// powers). The context is unusable afterwards.
            pub fn wipe(ctx: *Context) void {
                crypto.secureZero(u8, mem.asBytes(ctx));
            }
        };

        /// `Context.init(key)`.
        pub fn init(key: [key_length]u8) Context {
            return burn.run(burn.msg_burn, Context, Context.initBody, .{&key});
        }

        /// `Context.initWith(b, key)`.
        pub fn initWith(b: Backend, key: [key_length]u8) ?Context {
            return burn.run(burn.msg_burn, ?Context, Context.initWithBody, .{ b, &key });
        }

        /// `Context.initInto(out, key)`.
        pub fn initInto(out: *Context, key: *const [key_length]u8) void {
            burn.run(burn.msg_burn, void, Context.initIntoBody, .{ out, key });
        }

        /// `Context.initWithInto(out, b, key)`.
        pub fn initWithInto(out: *Context, b: Backend, key: *const [key_length]u8) bool {
            return burn.run(burn.msg_burn, bool, Context.initWithIntoBody, .{ out, b, key });
        }

        /// std's shape: `c`: ciphertext out, `tag`: tag out, `m`: plaintext,
        /// `ad`: associated data, `npub`: nonce, `key`: key. Same contract
        /// as `Context.encrypt`; derives the per-key state for this one call
        /// (only as many GHASH powers as the lengths need) and wipes it.
        ///
        /// Dead-stack: the entry point is burned (per message, tight), but
        /// `key` by value is still a copy in the caller's frame; `encryptInto`
        /// takes it by pointer.
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            burn.run(burn.msg_burn, void, encryptBody, .{ c, tag, m, ad, npub, &key });
        }

        /// `encrypt` with the key by pointer (the dead-stack-clean form).
        pub fn encryptInto(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: *const [key_length]u8) void {
            burn.run(burn.msg_burn, void, encryptBody, .{ c, tag, m, ad, npub, key });
        }

        fn encryptBody(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: *const [key_length]u8) void {
            assert(c.len == m.len);
            assert(m.len <= max_message_len);
            switch (backend()) {
                .generic => StdGcm.encrypt(c, tag, m, ad, npub, key.*),
                .aesni => if (x86_asm) {
                    var k = Ni.init(key.*, powersFor(ad.len, m.len));
                    defer wipeBlocks(@ptrCast(&k), @sizeOf(@TypeOf(k)) / 16);
                    k.seal(c, tag, m, ad, npub);
                } else unreachable,
            }
        }

        /// std's shape: `m`: plaintext out, `c`: ciphertext, `tag`, `ad`,
        /// `npub`, `key`. Same contract as `Context.decrypt`.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
            return burn.run(burn.msg_burn, AuthenticationError!void, decryptBody, .{ m, c, tag, ad, npub, &key });
        }

        /// `decrypt` with the key by pointer (the dead-stack-clean form).
        pub fn decryptInto(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: *const [key_length]u8) AuthenticationError!void {
            return burn.run(burn.msg_burn, AuthenticationError!void, decryptBody, .{ m, c, tag, ad, npub, key });
        }

        fn decryptBody(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: *const [key_length]u8) AuthenticationError!void {
            assert(c.len == m.len);
            assert(m.len <= max_message_len);
            switch (backend()) {
                .generic => StdGcm.decrypt(m, c, tag, ad, npub, key.*) catch |err| {
                    crypto.secureZero(u8, m);
                    return err;
                },
                .aesni => if (x86_asm) {
                    var k = Ni.init(key.*, powersFor(ad.len, m.len));
                    defer wipeBlocks(@ptrCast(&k), @sizeOf(@TypeOf(k)) / 16);
                    return k.open(m, c, tag, ad, npub);
                } else unreachable,
            }
        }

        /// The portable backend: std's primitives with the key schedule and
        /// H kept. H's powers are recomputed per message, as std does, sized
        /// to the message (`Ghash.initForBlockCount`): keeping std's sixteen
        /// would add 256 bytes to every context for a saving only long
        /// messages see.
        const Generic = struct {
            aes: crypto.core.aes.AesEncryptCtx(StdAes),
            h: [16]u8,

            fn init(key: [key_length]u8) Generic {
                const aes = StdAes.initEnc(key);
                var g: Generic = .{ .aes = aes, .h = undefined };
                aes.encrypt(&g.h, &@as([16]u8, @splat(0)));
                return g;
            }

            fn ghash(g: *const Generic, ad_len: usize, m_len: usize) Ghash {
                const blocks = (ad_len + 15) / 16 + (m_len + 15) / 16 + 1;
                return Ghash.initForBlockCount(&g.h, blocks);
            }

            /// `J0` and `E(K, J0)`.
            fn j0(g: *const Generic, npub: [nonce_length]u8) struct { [16]u8, [16]u8 } {
                var j: [16]u8 = undefined;
                j[0..nonce_length].* = npub;
                mem.writeInt(u32, j[nonce_length..][0..4], 1, .big);
                var t: [16]u8 = undefined;
                g.aes.encrypt(&t, &j);
                return .{ j, t };
            }

            fn finish(mac: *Ghash, ad_len: usize, m_len: usize, t: [16]u8, out: *[16]u8) void {
                var final_block: [16]u8 = undefined;
                mem.writeInt(u64, final_block[0..8], @as(u64, ad_len) * 8, .big);
                mem.writeInt(u64, final_block[8..16], @as(u64, m_len) * 8, .big);
                mac.update(&final_block);
                mac.final(out); // wipes `mac`
                for (out, t) |*o, x| o.* ^= x;
            }

            fn seal(g: *const Generic, c: []u8, tag: *[16]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) void {
                var j, var t = g.j0(npub);
                defer crypto.secureZero(u8, &t);
                var mac = g.ghash(ad.len, m.len);
                mac.update(ad);
                mac.pad();
                mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
                crypto.core.modes.ctr(@TypeOf(g.aes), g.aes, c, m, j, .big);
                mac.update(c);
                mac.pad();
                finish(&mac, ad.len, m.len, t, tag);
            }

            fn open(g: *const Generic, m: []u8, c: []const u8, tag: [16]u8, ad: []const u8, npub: [nonce_length]u8) AuthenticationError!void {
                var j, var t = g.j0(npub);
                defer crypto.secureZero(u8, &t);
                var mac = g.ghash(ad.len, c.len);
                mac.update(ad);
                mac.pad();
                mac.update(c);
                mac.pad();
                var computed: [16]u8 = undefined;
                defer crypto.secureZero(u8, &computed);
                finish(&mac, ad.len, c.len, t, &computed);
                if (!crypto.timing_safe.eql([16]u8, computed, tag)) {
                    crypto.secureZero(u8, m);
                    return error.AuthenticationFailed;
                }
                mem.writeInt(u32, j[nonce_length..][0..4], 2, .big);
                crypto.core.modes.ctr(@TypeOf(g.aes), g.aes, m, c, j, .big);
            }
        };
    };
}

/// SP 800-38D §5.2.1.1: plaintext up to 2^39 − 256 bits; with a 96-bit IV
/// the 32-bit counter starts at 2, so 2^32 − 2 blocks. The same bound std
/// asserts.
const max_message_len = 16 * ((1 << 32) - 2);

/// How many GHASH key powers a message with these lengths touches: the
/// widest aggregated group, at most eight blocks — for a short message the
/// single group of AD, ciphertext and length block; else the widest of the
/// AD groups and the ciphertext's last group plus the length block.
fn powersFor(ad_len: usize, m_len: usize) usize {
    const a = (ad_len + 15) / 16;
    const m = (m_len + 15) / 16;
    if (isShort(ad_len, m_len)) return a + m + 1;
    return std.math.clamp(@max(a, m + 1), 1, 8);
}

// ── dispatch ────────────────────────────────────────────────────────────────

/// The x86-64 kernel can be compiled at all: an x86-64 target and a backend
/// that passes vectors to inline assembly (the C backend does not) and can
/// encode AES-NI, PCLMULQDQ and SSSE3 for it. Zig 0.16's self-hosted x86_64
/// backend (the Debug default) encodes only what the target CPU model has,
/// so there the kernel exists only when the target guarantees all three;
/// LLVM assembles it for any x86_64 target.
const x86_asm = builtin.cpu.arch == .x86_64 and builtin.zig_backend != .stage2_c and
    (builtin.zig_backend != .stage2_x86_64 or
        (builtin.cpu.has(.x86, .aes) and builtin.cpu.has(.x86, .pclmul) and builtin.cpu.has(.x86, .ssse3)));

/// 0 = not yet detected, else `@intFromEnum(Backend) + 1`. Detection is
/// idempotent, so two threads racing to fill it store the same value.
var detected: std.atomic.Value(u8) = .init(0);

/// The backend the build target guarantees, when it guarantees one.
fn staticBackend() ?Backend {
    if (!x86_asm) return .generic;
    const f = builtin.cpu;
    if (f.has(.x86, .aes) and f.has(.x86, .pclmul) and f.has(.x86, .ssse3)) return .aesni;
    return null;
}

fn detect() Backend {
    return if (cpuidAesni()) .aesni else .generic;
}

fn cpuidAesni() bool {
    if (!x86_asm) return false;
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (@as(u32, 1)),
          [_] "{ecx}" (@as(u32, 0)),
    );
    // CPUID.01H:ECX — PCLMULQDQ bit 1, SSSE3 bit 9, AES bit 25.
    const need: u32 = (1 << 1) | (1 << 9) | (1 << 25);
    return ecx & need == need;
}

// ── x86-64: AES-NI + PCLMULQDQ ──────────────────────────────────────────────
//
// GHASH representation (Gueron–Kounavis, "Intel Carry-Less Multiplication
// Instruction and its Usage for Computing the GCM Mode", rev. 2.02, and std's
// `ghash_polyval`): a 16-byte block is byte-reversed into a 128-bit integer
// (`pshufb`), so bit i is the coefficient of x^(127−i). The carry-less
// product of two such integers is then the reflected product shifted by one
// bit; instead of shifting every product back, H is stored pre-multiplied by
// x ("shifted H"), and every power H^k is kept in that same form, because
// f(u, v) = reduce(u·v) maps (X, H·x) to X·H and (H^a·x, H^b·x) to H^(a+b)·x.
// The 256-bit product is reduced modulo x^128 + x^127 + x^126 + x^121 + 1 by
// two further multiplications with 0xC2 << 56 (the "two-phase" reduction of
// the same paper).
//
// Counters are kept byte-reversed too: then the 32-bit big-endian counter is
// the low dword, `paddd` increments it modulo 2^32 exactly as SP 800-38D's
// inc32 does (the upper 96 bits never change), and a `pshufb` turns it back
// into the block AES encrypts.

const V = @Vector(2, u64);
const zero_v: V = @splat(0);

/// Register-only inline assembly: the self-hosted x86 backend (Zig 0.16
/// Debug) cannot size an SSE memory operand, and every load is Zig's anyway.
/// VEX forms when the build target has AVX (no false dependencies, no
/// SSE/AVX transitions next to compiler-generated AVX code), legacy SSE
/// forms otherwise, so a baseline build runs on any CPU whose CPUID reports
/// the instructions.
const Isa = struct {
    const vex = builtin.cpu.has(.x86, .avx);
    const ssse3 = builtin.cpu.has(.x86, .ssse3);

    inline fn aesenc(b: V, k: V) V {
        if (comptime vex) return asm ("vaesenc %[k], %[b], %[o]"
            : [o] "=x" (-> V),
            : [b] "x" (b),
              [k] "x" (k),
        );
        return asm ("aesenc %[k], %[b]"
            : [b] "=x" (-> V),
            : [_] "0" (b),
              [k] "x" (k),
        );
    }

    inline fn aesenclast(b: V, k: V) V {
        if (comptime vex) return asm ("vaesenclast %[k], %[b], %[o]"
            : [o] "=x" (-> V),
            : [b] "x" (b),
              [k] "x" (k),
        );
        return asm ("aesenclast %[k], %[b]"
            : [b] "=x" (-> V),
            : [_] "0" (b),
              [k] "x" (k),
        );
    }

    /// One `pclmulqdq`: the qword of `a` picked by imm bit 0 times the qword
    /// of `b` picked by imm bit 4.
    inline fn clmul(comptime imm: u8, a: V, b: V) V {
        if (comptime vex) return asm (std.fmt.comptimePrint("vpclmulqdq $0x{x:0>2}, %[b], %[a], %[o]", .{imm})
            : [o] "=x" (-> V),
            : [a] "x" (a),
              [b] "x" (b),
        );
        return asm (std.fmt.comptimePrint("pclmulqdq $0x{x:0>2}, %[b], %[a]", .{imm})
            : [a] "=x" (-> V),
            : [_] "0" (a),
              [b] "x" (b),
        );
    }

    /// `pshufb` with a constant index vector. Through the compiler when the
    /// target has SSSE3 (it can then fold the mask load), else assembly.
    inline fn shuffle(x: V, comptime idx: [16]u8) V {
        if (comptime ssse3) {
            const mask: [16]i32 = comptime blk: {
                var m: [16]i32 = undefined;
                for (&m, idx) |*o, i| o.* = i;
                break :blk m;
            };
            return @bitCast(@shuffle(u8, @as(@Vector(16, u8), @bitCast(x)), undefined, mask));
        }
        const m: V = @bitCast(idx);
        return asm ("pshufb %[m], %[x]"
            : [x] "=x" (-> V),
            : [_] "0" (x),
              [m] "x" (m),
        );
    }
};

const reverse_idx: [16]u8 = .{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

inline fn bswap(x: V) V {
    return Isa.shuffle(x, reverse_idx);
}

/// Zero `n` 16-byte blocks at `p` with volatile stores: `secureZero`'s
/// guarantee (the compiler may not drop them) at one store per block, not
/// per byte — a 128-byte tail buffer wiped bytewise cost more than the
/// whole 64-byte message it had carried.
fn wipeBlocks(p: [*]u8, n: usize) void {
    const v: [*]align(1) volatile V = @ptrCast(p);
    for (0..n) |i| v[i] = zero_v;
}

inline fn load(p: *const [16]u8) V {
    return @bitCast(p.*);
}

inline fn store(p: *[16]u8, v: V) void {
    p.* = @bitCast(v);
}

/// The byte-reversed counter block `ctr` advanced by `n` (inc32, n times).
inline fn ctrAdd(ctr: V, n: u32) V {
    const w: @Vector(4, u32) = @bitCast(ctr);
    return @bitCast(w +% @Vector(4, u32){ n, 0, 0, 0 });
}

/// A 256-bit carry-less product, as three 128-bit parts: `lo`, `hi` and the
/// middle term `mid` that straddles them.
const Acc = struct {
    lo: V = zero_v,
    hi: V = zero_v,
    mid: V = zero_v,

    /// += x·y, schoolbook: four `pclmulqdq`. (Karatsuba saves one multiply
    /// but costs a shuffle on the same port on Skylake-class cores.)
    inline fn mulAdd(g: *Acc, x: V, y: V) void {
        g.lo ^= Isa.clmul(0x00, x, y);
        g.hi ^= Isa.clmul(0x11, x, y);
        g.mid ^= Isa.clmul(0x01, x, y) ^ Isa.clmul(0x10, x, y);
    }

    /// The product reduced modulo the GCM polynomial.
    inline fn reduce(g: Acc) V {
        const p: V = .{ 0xc200_0000_0000_0000, 0 };
        const hi = g.hi ^ @shuffle(u64, g.mid, zero_v, [2]i32{ 1, -1 });
        const lo = g.lo ^ @shuffle(u64, g.mid, zero_v, [2]i32{ -1, 0 });
        const a = Isa.clmul(0x00, lo, p);
        const b = @shuffle(u64, lo, undefined, [2]i32{ 1, 0 }) ^ a;
        const c = Isa.clmul(0x00, b, p);
        return @shuffle(u64, b, undefined, [2]i32{ 1, 0 }) ^ c ^ hi;
    }
};

inline fn gmul(x: V, y: V) V {
    var g: Acc = .{};
    g.mulAdd(x, y);
    return g.reduce();
}

/// acc ← (acc ⊕ X₀)·H^n ⊕ X₁·H^(n−1) ⊕ … ⊕ X_(n−1)·H over the first `n`
/// (1…8) blocks of `blocks`, one reduction.
fn ghashN(h: *const [8]V, acc: V, blocks: *const [128]u8, n: usize) V {
    assert(n >= 1 and n <= 8);
    var g: Acc = .{};
    var x = bswap(load(blocks[0..16])) ^ acc;
    g.mulAdd(x, h[n - 1]);
    var j: usize = 1;
    while (j < n) : (j += 1) {
        x = bswap(load(blocks[16 * j ..][0..16]));
        g.mulAdd(x, h[n - 1 - j]);
    }
    return g.reduce();
}

/// `ghashN` for exactly eight blocks, unrolled.
inline fn ghash8(h: *const [8]V, acc: V, blocks: *const [128]u8) V {
    var g: Acc = .{};
    inline for (0..8) |j| {
        var x = bswap(load(blocks[16 * j ..][0..16]));
        if (j == 0) x ^= acc;
        g.mulAdd(x, h[7 - j]);
    }
    return g.reduce();
}

/// GHASH of `data` zero-padded to whole blocks, continuing from `acc`.
fn ghashBytes(h: *const [8]V, acc: V, data: []const u8) V {
    var a = acc;
    var p = data;
    while (p.len >= 128) : (p = p[128..]) a = ghash8(h, a, p[0..128]);
    if (p.len > 0) {
        var buf: [128]u8 = @splat(0);
        @memcpy(buf[0..p.len], p);
        a = ghashN(h, a, &buf, (p.len + 15) / 16);
    }
    return a;
}

/// A message short enough that its AD, its ciphertext and the length block
/// fit one aggregated GHASH group of at most eight blocks.
fn isShort(ad_len: usize, m_len: usize) bool {
    return (ad_len + 15) / 16 + (m_len + 15) / 16 < 8;
}

/// GHASH from `acc` over the first `n` (0…8) blocks of `buf` and then the
/// length block `lens`, as one group when they fit (writing `lens` into
/// `buf` after them), else as two.
fn finishGhash(h: *const [8]V, acc: V, buf: *[128]u8, n: usize, lens: V) V {
    if (n < 8) {
        store(buf[16 * n ..][0..16], bswap(lens));
        return ghashN(h, acc, buf, n + 1);
    }
    return gmul(ghashN(h, acc, buf, n) ^ lens, h[0]);
}

/// H·x, from the byte-reversed H: the "shifted H" every product assumes.
fn shiftH(h_rev: V) V {
    var u: u128 = @bitCast(h_rev);
    const carry = ((@as(u128, 0xc2) << 120) | 1) & (@as(u128, 0) -% (u >> 127));
    u = (u << 1) ^ carry;
    return @bitCast(u);
}

/// Expanded key and GHASH powers for the x86-64 kernel.
fn NiKey(comptime key_bits: u16) type {
    return struct {
        const Self = @This();
        const nr = if (key_bits == 128) 10 else 14;

        /// AES round keys 0 … nr.
        rk: [nr + 1]V,
        /// h[i] = H^(i+1), shifted form. Only the first `init`'s `npow`
        /// are defined.
        h: [8]V,

        fn init(key: [key_bits / 8]u8, npow: usize) Self {
            var k: Self = undefined;
            k.rk = expand(key);
            k.h[0] = shiftH(bswap(k.encBlock(zero_v)));
            if (npow >= 2) k.h[1] = gmul(k.h[0], k.h[0]);
            if (npow >= 3) k.h[2] = gmul(k.h[1], k.h[0]);
            if (npow >= 4) k.h[3] = gmul(k.h[1], k.h[1]);
            if (npow >= 5) k.h[4] = gmul(k.h[3], k.h[0]);
            if (npow >= 6) k.h[5] = gmul(k.h[3], k.h[1]);
            if (npow >= 7) k.h[6] = gmul(k.h[3], k.h[2]);
            if (npow >= 8) k.h[7] = gmul(k.h[3], k.h[3]);
            return k;
        }

        /// FIPS-197 key expansion with `aesenclast` doing SubWord: a state
        /// whose four columns are equal is unchanged by ShiftRows, so
        /// `aesenclast(RotWord(w)×4, rcon×4)` is SubWord(RotWord(w)) ⊕ rcon in
        /// every column (Gueron, "Intel AES New Instructions Set", rev. 3.01,
        /// §5.2 alternative to `aeskeygenassist`). Constant time: no table.
        fn expand(key: [key_bits / 8]u8) [nr + 1]V {
            const rot3 = comptime rep4(.{ 13, 14, 15, 12 }); // RotWord(w3) in every column
            const dup3 = comptime rep4(.{ 12, 13, 14, 15 }); // w3 in every column
            const rcon = [_]u32{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
            var rk: [nr + 1]V = undefined;
            if (key_bits == 128) {
                var k = load(key[0..16]);
                rk[0] = k;
                inline for (1..11) |i| {
                    const t = Isa.aesenclast(Isa.shuffle(k, rot3), splat32(rcon[i - 1]));
                    k = prefixXor(k) ^ t;
                    rk[i] = k;
                }
            } else {
                var a = load(key[0..16]);
                var b = load(key[16..32]);
                rk[0] = a;
                rk[1] = b;
                inline for (1..8) |i| {
                    a = prefixXor(a) ^ Isa.aesenclast(Isa.shuffle(b, rot3), splat32(rcon[i - 1]));
                    rk[2 * i] = a;
                    if (i < 7) {
                        b = prefixXor(b) ^ Isa.aesenclast(Isa.shuffle(a, dup3), zero_v);
                        rk[2 * i + 1] = b;
                    }
                }
            }
            return rk;
        }

        inline fn encBlock(k: *const Self, x: V) V {
            var b = x ^ k.rk[0];
            inline for (1..nr) |r| b = Isa.aesenc(b, k.rk[r]);
            return Isa.aesenclast(b, k.rk[nr]);
        }

        /// Eight counter blocks from `ctr` through AES, XORed over `in` into
        /// `out`, while the eight blocks at `gh` are folded into GHASH from
        /// `acc` — the stitched step. Returns the new GHASH value. `out` may
        /// be `in`; `gh` is read before `out` is written.
        inline fn batch(k: *const Self, ctr: V, acc: V, gh: *const [128]u8, out: *[128]u8, in: *const [128]u8) V {
            var b: [8]V = undefined;
            inline for (0..8) |j| b[j] = bswap(ctrAdd(ctr, j)) ^ k.rk[0];
            var g: Acc = .{};
            inline for (1..nr) |r| {
                const rk = k.rk[r];
                inline for (0..8) |j| b[j] = Isa.aesenc(b[j], rk);
                if (r <= 8) {
                    const j = r - 1;
                    var x = bswap(load(gh[16 * j ..][0..16]));
                    if (j == 0) x ^= acc;
                    g.mulAdd(x, k.h[7 - j]);
                }
            }
            const last = k.rk[nr];
            inline for (0..8) |j| {
                const ks = Isa.aesenclast(b[j], last);
                store(out[16 * j ..][0..16], load(in[16 * j ..][0..16]) ^ ks);
            }
            return g.reduce();
        }

        /// Eight counter blocks, no GHASH.
        inline fn ctr8(k: *const Self, ctr: V, out: *[128]u8, in: *const [128]u8) void {
            var b: [8]V = undefined;
            inline for (0..8) |j| b[j] = bswap(ctrAdd(ctr, j)) ^ k.rk[0];
            inline for (1..nr) |r| {
                const rk = k.rk[r];
                inline for (0..8) |j| b[j] = Isa.aesenc(b[j], rk);
            }
            inline for (0..8) |j| {
                const ks = Isa.aesenclast(b[j], k.rk[nr]);
                store(out[16 * j ..][0..16], load(in[16 * j ..][0..16]) ^ ks);
            }
        }

        /// XOR the keystream from `ctr` over the `n` blocks of `buf`.
        fn ctrBlocks(k: *const Self, ctr: V, buf: []u8, n: usize) void {
            var j: usize = 0;
            while (j < n) : (j += 1) {
                const ks = k.encBlock(bswap(ctrAdd(ctr, @intCast(j))));
                const p = buf[16 * j ..][0..16];
                store(p, load(p) ^ ks);
            }
        }

        /// The last `m.len < 128` bytes (possibly none) and the length
        /// block, with `ad` in front of them when the caller has not hashed
        /// it yet: all laid out in one zeroed 128-byte buffer and hashed as
        /// ONE aggregated group when they fit in eight blocks, so a short
        /// record pays one GHASH reduction instead of three. Returns S.
        fn sealTail(k: *const Self, ctr: V, acc: V, c: []u8, m: []const u8, ad: []const u8, lens: V) V {
            const off = 16 * ((ad.len + 15) / 16);
            const nb = (m.len + 15) / 16;
            assert(off + 16 * nb <= 128);
            var buf: [128]u8 = @splat(0);
            defer wipeBlocks(&buf, 8);
            @memcpy(buf[0..ad.len], ad);
            @memcpy(buf[off..][0..m.len], m);
            k.ctrBlocks(ctr, buf[off..][0 .. 16 * nb], nb);
            @memcpy(c, buf[off..][0..m.len]);
            @memset(buf[off + m.len .. off + 16 * nb], 0);
            return finishGhash(&k.h, acc, &buf, off / 16 + nb, lens);
        }

        /// `sealTail` for decryption: hash first, then decrypt.
        fn openTail(k: *const Self, ctr: V, acc: V, m: []u8, c: []const u8, ad: []const u8, lens: V) V {
            const off = 16 * ((ad.len + 15) / 16);
            const nb = (c.len + 15) / 16;
            assert(off + 16 * nb <= 128);
            var buf: [128]u8 = @splat(0);
            defer wipeBlocks(&buf, 8);
            @memcpy(buf[0..ad.len], ad);
            @memcpy(buf[off..][0..c.len], c);
            const s = finishGhash(&k.h, acc, &buf, off / 16 + nb, lens);
            k.ctrBlocks(ctr, buf[off..][0 .. 16 * nb], nb);
            @memcpy(m, buf[off..][0..c.len]);
            return s;
        }

        /// CTR-encrypt `m` into `c` from the byte-reversed counter `ctr`,
        /// with GHASH from `acc` over `ad` (non-empty only when `m` is
        /// shorter than one batch), the ciphertext and the length block
        /// `lens`; returns S.
        fn sealBody(k: *const Self, ctr0: V, acc0: V, c: []u8, m: []const u8, ad: []const u8, lens: V) V {
            const n = m.len;
            var acc = acc0;
            var ctr = ctr0;
            var i: usize = 0;
            if (n >= 128) {
                assert(ad.len == 0);
                // The first eight blocks have no ciphertext before them to
                // hash; every later batch hashes the one it follows, and
                // the last one is hashed on its own.
                k.ctr8(ctr, c[0..128], m[0..128]);
                ctr = ctrAdd(ctr, 8);
                i = 128;
                while (n - i >= 128) : (i += 128) {
                    acc = k.batch(ctr, acc, c[i - 128 ..][0..128], c[i..][0..128], m[i..][0..128]);
                    ctr = ctrAdd(ctr, 8);
                }
                acc = ghash8(&k.h, acc, c[i - 128 ..][0..128]);
            }
            return k.sealTail(ctr, acc, c[i..], m[i..], ad, lens);
        }

        /// CTR-decrypt `c` into `m`, GHASH as `sealBody`; returns S. The
        /// ciphertext is there from the start, so GHASH runs one batch
        /// AHEAD of the decryption: batch i's AES is stitched with batch
        /// i+1's GHASH. Hashing the batch being decrypted would let the
        /// compiler merge the two loads of each block and keep eight more
        /// registers live across the rounds (measured: half the speed), and
        /// hashing the one behind would read plaintext when `m` is `c`.
        fn openBody(k: *const Self, ctr0: V, acc0: V, m: []u8, c: []const u8, ad: []const u8, lens: V) V {
            const n = c.len;
            var acc = acc0;
            var ctr = ctr0;
            var i: usize = 0;
            if (n >= 128) {
                assert(ad.len == 0);
                acc = ghash8(&k.h, acc, c[0..128]);
                while (n - i >= 256) : (i += 128) {
                    acc = k.batch(ctr, acc, c[i + 128 ..][0..128], m[i..][0..128], c[i..][0..128]);
                    ctr = ctrAdd(ctr, 8);
                }
                k.ctr8(ctr, m[i..][0..128], c[i..][0..128]);
                ctr = ctrAdd(ctr, 8);
                i += 128;
            }
            return k.openTail(ctr, acc, m[i..], c[i..], ad, lens);
        }

        fn j0Block(npub: [12]u8) V {
            return load(&(npub ++ [4]u8{ 0, 0, 0, 1 }));
        }

        /// The length block [len(A)]₆₄ ‖ [len(C)]₆₄ in bits, byte-reversed.
        fn lengths(ad_len: usize, m_len: usize) V {
            return .{ @as(u64, m_len) * 8, @as(u64, ad_len) * 8 };
        }

        fn seal(k: *const Self, c: []u8, t: *[16]u8, m: []const u8, ad: []const u8, npub: [12]u8) void {
            const j0 = j0Block(npub);
            const ctr = ctrAdd(bswap(j0), 1);
            const lens = lengths(ad.len, m.len);
            const s = if (isShort(ad.len, m.len))
                k.sealBody(ctr, zero_v, c, m, ad, lens)
            else
                k.sealBody(ctr, ghashBytes(&k.h, zero_v, ad), c, m, "", lens);
            store(t, bswap(s) ^ k.encBlock(j0));
        }

        fn open(k: *const Self, m: []u8, c: []const u8, t: [16]u8, ad: []const u8, npub: [12]u8) AuthenticationError!void {
            const j0 = j0Block(npub);
            const ctr = ctrAdd(bswap(j0), 1);
            const lens = lengths(ad.len, c.len);
            const s = if (isShort(ad.len, c.len))
                k.openBody(ctr, zero_v, m, c, ad, lens)
            else
                k.openBody(ctr, ghashBytes(&k.h, zero_v, ad), m, c, "", lens);
            var computed: [16]u8 = undefined;
            defer wipeBlocks(&computed, 1);
            store(&computed, bswap(s) ^ k.encBlock(j0));
            if (!crypto.timing_safe.eql([16]u8, computed, t)) {
                crypto.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
        }
    };
}

fn rep4(comptime w: [4]u8) [16]u8 {
    return w ++ w ++ w ++ w;
}

inline fn splat32(x: u32) V {
    return @bitCast(@as(@Vector(4, u32), @splat(x)));
}

/// (w0, w1⊕w0, w2⊕w1⊕w0, w3⊕w2⊕w1⊕w0): the running XOR of a round key's
/// words, which the next round key needs.
inline fn prefixXor(k: V) V {
    const z: @Vector(4, u32) = @splat(0);
    const w: @Vector(4, u32) = @bitCast(k);
    const a = w ^ @shuffle(u32, w, z, [4]i32{ -1, 0, 1, 2 });
    return @bitCast(a ^ @shuffle(u32, a, z, [4]i32{ -1, -1, 0, 1 }));
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const all_backends = [_]Backend{ .generic, .aesni };

fn hexBytes(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// Every backend this CPU has, plus the stateless path, must produce
/// `want_c`/`want_tag`, and decrypt it back.
fn expectVector(comptime Gcm: type, key: [Gcm.key_length]u8, iv: [12]u8, p: []const u8, ad: []const u8, want_c: []const u8, want_tag: [16]u8) !void {
    var c: [64]u8 = undefined;
    var m: [64]u8 = undefined;
    var t: [16]u8 = undefined;
    var ran: usize = 0;
    for (all_backends) |b| {
        var ctx = Gcm.initWith(b, key) orelse continue;
        defer ctx.wipe();
        ctx.encrypt(c[0..p.len], &t, p, ad, iv);
        try testing.expectEqualSlices(u8, want_c, c[0..p.len]);
        try testing.expectEqualSlices(u8, &want_tag, &t);
        try ctx.decrypt(m[0..p.len], want_c, want_tag, ad, iv);
        try testing.expectEqualSlices(u8, p, m[0..p.len]);
        ran += 1;
    }
    try testing.expect(ran >= 1);
    Gcm.encrypt(c[0..p.len], &t, p, ad, iv, key);
    try testing.expectEqualSlices(u8, want_c, c[0..p.len]);
    try testing.expectEqualSlices(u8, &want_tag, &t);
    try Gcm.decrypt(m[0..p.len], want_c, want_tag, ad, iv, key);
    try testing.expectEqualSlices(u8, p, m[0..p.len]);
}

const gcm_p = hexBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" ++
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
const gcm_a = hexBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
const gcm_iv = hexBytes("cafebabefacedbaddecaf888");

test "McGrew–Viega GCM test cases 1–4 (AES-128)" {
    // "The Galois/Counter Mode of Operation (GCM)", McGrew & Viega, 2005,
    // appendix B — the vectors NIST's GCM validation suite grew from.
    const z16: [16]u8 = @splat(0);
    const z12: [12]u8 = @splat(0);
    try expectVector(Aes128Gcm, z16, z12, "", "", "", hexBytes("58e2fccefa7e3061367f1d57a4e7455a"));
    try expectVector(Aes128Gcm, z16, z12, &z16, "", &hexBytes("0388dace60b6a392f328c2b971b2fe78"), hexBytes("ab6e47d42cec13bdf53a67b21257bddf"));
    const k = hexBytes("feffe9928665731c6d6a8f9467308308");
    const c3 = hexBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" ++
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985");
    try expectVector(Aes128Gcm, k, gcm_iv, &gcm_p, "", &c3, hexBytes("4d5c2af327cd64a62cf35abd2ba6fab4"));
    try expectVector(Aes128Gcm, k, gcm_iv, gcm_p[0..60], &gcm_a, c3[0..60], hexBytes("5bc94fbc3221a5db94fae95ae7121a47"));
}

test "McGrew–Viega GCM test cases 13–16 (AES-256)" {
    const z32: [32]u8 = @splat(0);
    const z16: [16]u8 = @splat(0);
    const z12: [12]u8 = @splat(0);
    try expectVector(Aes256Gcm, z32, z12, "", "", "", hexBytes("530f8afbc74536b9a963b4f1c4cb738b"));
    try expectVector(Aes256Gcm, z32, z12, &z16, "", &hexBytes("cea7403d4d606b6e074ec5d3baf39d18"), hexBytes("d0d1c8a799996bf0265b98b5d48ab919"));
    const k = hexBytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const c15 = hexBytes("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" ++
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
    try expectVector(Aes256Gcm, k, gcm_iv, &gcm_p, "", &c15, hexBytes("b094dac5d93471bdec1a502270e3cc6c"));
    try expectVector(Aes256Gcm, k, gcm_iv, gcm_p[0..60], &gcm_a, c15[0..60], hexBytes("76fc6ece0f4e1768cddf8853bb2d551b"));
}

/// Deterministic test bytes: `seed`-dependent, position-dependent.
fn pattern(buf: []u8, seed: u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% @as(usize, seed) *% 101 +% (i >> 8) *% 7);
}

// Long-message vectors from OpenSSL (through Python `cryptography`), made by
// `tools/openssl_kat.py`: key, nonce, AD and plaintext are `pattern` bytes
// (seeds 1, 2, 3, 4), and the table holds the tag and SHA-256(ciphertext).
// These are the only external anchor that reaches the stitched eight-block
// loop, whose shortest input is 256 bytes.
const openssl_kats = @import("testdata/openssl_kat.zig").vectors;

test "long messages agree with OpenSSL (tools/openssl_kat.py)" {
    const buf = try testing.allocator.alloc(u8, 3 * 20_000);
    defer testing.allocator.free(buf);
    inline for (.{ Aes128Gcm, Aes256Gcm }) |Gcm| {
        var key: [Gcm.key_length]u8 = undefined;
        var iv: [12]u8 = undefined;
        pattern(&key, 1);
        pattern(&iv, 2);
        var seen: usize = 0;
        for (openssl_kats) |v| {
            if (v.bits != Gcm.key_length * 8) continue;
            seen += 1;
            const ad = buf[0..v.ad_len];
            const m = buf[20_000..][0..v.m_len];
            const c = buf[40_000..][0..v.m_len];
            pattern(ad, 3);
            pattern(m, 4);
            const want_tag = try hexAlloc(v.tag);
            defer testing.allocator.free(want_tag);
            const want_sha = try hexAlloc(v.ct_sha256);
            defer testing.allocator.free(want_sha);
            for (all_backends) |b| {
                var ctx = Gcm.initWith(b, key) orelse continue;
                var t: [16]u8 = undefined;
                ctx.encrypt(c, &t, m, ad, iv);
                try testing.expectEqualSlices(u8, want_tag, &t);
                var d: [32]u8 = undefined;
                crypto.hash.sha2.Sha256.hash(c, &d, .{});
                try testing.expectEqualSlices(u8, want_sha, &d);
                try ctx.decrypt(c, c, t, ad, iv);
                try testing.expectEqualSlices(u8, m, c);
            }
        }
        try testing.expect(seen >= 10);
    }
}

// Wycheproof's AES-GCM vectors (C2SP/wycheproof, Apache-2.0 data -- see
// NOTICE), made by `tools/wycheproof.py`: every test with a 128/256-bit key,
// a 96-bit IV and a 128-bit tag. 79 valid, 54 with a modified tag that must
// be refused -- third-party rejection cases, where the other anchors only
// have our own bit flips.
const wycheproof = @import("testdata/wycheproof.zig").vectors;

test "Wycheproof aes_gcm_test.json: valid vectors encrypt, modified tags are refused" {
    var counts = [2]usize{ 0, 0 };
    inline for (.{ Aes128Gcm, Aes256Gcm }) |Gcm| {
        for (wycheproof) |v| {
            if (v.bits != Gcm.key_length * 8) continue;
            counts[@intFromBool(v.valid)] += 1;
            var key: [Gcm.key_length]u8 = undefined;
            var iv: [12]u8 = undefined;
            var tag: [16]u8 = undefined;
            _ = try std.fmt.hexToBytes(&key, v.key);
            _ = try std.fmt.hexToBytes(&iv, v.iv);
            _ = try std.fmt.hexToBytes(&tag, v.tag);
            const aad = try hexAlloc(v.aad);
            defer testing.allocator.free(aad);
            const msg = try hexAlloc(v.msg);
            defer testing.allocator.free(msg);
            const ct = try hexAlloc(v.ct);
            defer testing.allocator.free(ct);
            const out = try testing.allocator.alloc(u8, msg.len);
            defer testing.allocator.free(out);

            for (all_backends) |b| {
                var ctx = Gcm.initWith(b, key) orelse continue;
                if (v.valid) {
                    var t: [16]u8 = undefined;
                    ctx.encrypt(out, &t, msg, aad, iv);
                    try testing.expectEqualSlices(u8, ct, out);
                    try testing.expectEqualSlices(u8, &tag, &t);
                    try ctx.decrypt(out, ct, tag, aad, iv);
                    try testing.expectEqualSlices(u8, msg, out);
                } else {
                    @memset(out, 0xaa);
                    try testing.expectError(error.AuthenticationFailed, ctx.decrypt(out, ct, tag, aad, iv));
                    for (out) |byte| try testing.expectEqual(@as(u8, 0), byte); // wiped, not plaintext
                }
            }
            // The stateless path too.
            if (v.valid) {
                var t: [16]u8 = undefined;
                Gcm.encrypt(out, &t, msg, aad, iv, key);
                try testing.expectEqualSlices(u8, ct, out);
                try testing.expectEqualSlices(u8, &tag, &t);
            } else {
                try testing.expectError(error.AuthenticationFailed, Gcm.decrypt(out, ct, tag, aad, iv, key));
            }
        }
    }
    // Pinned so a regenerated table that silently lost a class shows here.
    try testing.expectEqual(@as(usize, 79), counts[1]);
    try testing.expectEqual(@as(usize, 54), counts[0]);
}

fn hexAlloc(s: []const u8) ![]u8 {
    const out = try testing.allocator.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

/// One random case against std: stateless and every backend's context,
/// encrypt out-of-place and in-place, decrypt both ways.
fn diffOne(comptime Gcm: type, rnd: std.Random, buf: []u8, m_len: usize, ad_len: usize) !void {
    const Std = if (Gcm.key_length == 16) crypto.aead.aes_gcm.Aes128Gcm else crypto.aead.aes_gcm.Aes256Gcm;
    var key: [Gcm.key_length]u8 = undefined;
    var iv: [12]u8 = undefined;
    var ad_buf: [128]u8 = undefined;
    rnd.bytes(&key);
    rnd.bytes(&iv);
    const ad = ad_buf[0..ad_len];
    rnd.bytes(ad);
    const m = buf[0..m_len];
    const want_c = buf[m_len..][0..m_len];
    const got = buf[2 * m_len ..][0..m_len];
    rnd.bytes(m);
    var want_t: [16]u8 = undefined;
    Std.encrypt(want_c, &want_t, m, ad, iv, key);

    var t: [16]u8 = undefined;
    Gcm.encrypt(got, &t, m, ad, iv, key);
    try testing.expectEqualSlices(u8, want_c, got);
    try testing.expectEqualSlices(u8, &want_t, &t);
    try Gcm.decrypt(got, want_c, want_t, ad, iv, key);
    try testing.expectEqualSlices(u8, m, got);

    for (all_backends) |b| {
        var ctx = Gcm.initWith(b, key) orelse continue;
        defer ctx.wipe();
        @memset(got, 0);
        ctx.encrypt(got, &t, m, ad, iv);
        try testing.expectEqualSlices(u8, want_c, got);
        try testing.expectEqualSlices(u8, &want_t, &t);
        // In place: encrypt m's copy over itself, then decrypt it back.
        @memcpy(got, m);
        ctx.encrypt(got, &t, got, ad, iv);
        try testing.expectEqualSlices(u8, want_c, got);
        try testing.expectEqualSlices(u8, &want_t, &t);
        try ctx.decrypt(got, got, t, ad, iv);
        try testing.expectEqualSlices(u8, m, got);
    }
}

test "differential against std: every length 0…300, AD 0…64, both key sizes" {
    const buf = try testing.allocator.alloc(u8, 3 * 300);
    defer testing.allocator.free(buf);
    var prng = std.Random.DefaultPrng.init(0xae5_6c1);
    const rnd = prng.random();
    for (0..301) |n| {
        const ad_len = n % 65;
        try diffOne(Aes128Gcm, rnd, buf, n, ad_len);
        try diffOne(Aes256Gcm, rnd, buf, n, 64 - ad_len);
    }
}

test "differential against std: random lengths up to 20 000" {
    const max = 20_000;
    const buf = try testing.allocator.alloc(u8, 3 * max);
    defer testing.allocator.free(buf);
    var prng = std.Random.DefaultPrng.init(0x5eed_a35);
    const rnd = prng.random();
    for (0..1500) |i| {
        // Half the cases near a batch boundary, where the paths change.
        const n = if (i % 2 == 0)
            rnd.uintAtMost(usize, max)
        else
            @min(max, 128 * rnd.uintAtMost(usize, 40) + rnd.uintAtMost(usize, 32) -| 16);
        const ad_len = rnd.uintAtMost(usize, 128);
        if (i % 2 == 0) try diffOne(Aes128Gcm, rnd, buf, n, ad_len) else try diffOne(Aes256Gcm, rnd, buf, n, ad_len);
    }
}

test "the output may start before the input: a record decrypted over its own header" {
    // `tls.zig`'s client decrypts a record into the buffer that starts at
    // the record's 5-byte header (`handshake_client.zig`, `@constCast(rec.
    // buffer)`), i.e. `m` = `c` − 5. Every path reads input before it writes
    // the output behind it, so such a forward overlap works — as it does in
    // std, whose CTR runs front to back — for both directions.
    var prng = std.Random.DefaultPrng.init(0x0e1a9);
    const rnd = prng.random();
    var key: [32]u8 = undefined;
    var iv: [12]u8 = undefined;
    var ad: [13]u8 = undefined;
    rnd.bytes(&key);
    rnd.bytes(&iv);
    rnd.bytes(&ad);
    var m: [700]u8 = undefined;
    rnd.bytes(&m);
    var want_c: [700]u8 = undefined;
    var buf: [720]u8 = undefined;
    for ([_]usize{ 0, 1, 15, 16, 100, 128, 255, 256, 300, 700 }) |n| {
        var want_t: [16]u8 = undefined;
        crypto.aead.aes_gcm.Aes256Gcm.encrypt(want_c[0..n], &want_t, m[0..n], &ad, iv, key);
        for ([_]usize{ 1, 5, 16, 17 }) |shift| {
            for (all_backends) |b| {
                var ctx = Aes256Gcm.initWith(b, key) orelse continue;
                defer ctx.wipe();
                // Decrypt: ciphertext at `shift`, plaintext to 0.
                @memcpy(buf[shift..][0..n], want_c[0..n]);
                try ctx.decrypt(buf[0..n], buf[shift..][0..n], want_t, &ad, iv);
                try testing.expectEqualSlices(u8, m[0..n], buf[0..n]);
                // Encrypt: plaintext at `shift`, ciphertext to 0.
                @memcpy(buf[shift..][0..n], m[0..n]);
                var t: [16]u8 = undefined;
                ctx.encrypt(buf[0..n], &t, buf[shift..][0..n], &ad, iv);
                try testing.expectEqualSlices(u8, want_c[0..n], buf[0..n]);
                try testing.expectEqualSlices(u8, &want_t, &t);
            }
        }
    }
}

test "the stateless functions compute exactly the GHASH powers they use" {
    // Every length class around the power thresholds, with AD longer or
    // shorter than the message: a power left undefined shows up as a
    // mismatch against the full context.
    var prng = std.Random.DefaultPrng.init(99);
    const rnd = prng.random();
    var m: [300]u8 = undefined;
    var ad: [300]u8 = undefined;
    rnd.bytes(&m);
    rnd.bytes(&ad);
    var key: [16]u8 = undefined;
    rnd.bytes(&key);
    const iv: [12]u8 = @splat(7);
    var ctx = Aes128Gcm.init(key);
    defer ctx.wipe();
    for ([_]usize{ 0, 1, 16, 17, 33, 64, 80, 96, 97, 100, 112, 113, 127, 128, 129, 255, 256, 300 }) |ml| {
        for ([_]usize{ 0, 5, 13, 16, 17, 50, 112, 113, 127, 128, 200, 300 }) |al| {
            var c1: [300]u8 = undefined;
            var c2: [300]u8 = undefined;
            var t1: [16]u8 = undefined;
            var t2: [16]u8 = undefined;
            Aes128Gcm.encrypt(c1[0..ml], &t1, m[0..ml], ad[0..al], iv, key);
            ctx.encrypt(c2[0..ml], &t2, m[0..ml], ad[0..al], iv);
            try testing.expectEqualSlices(u8, c2[0..ml], c1[0..ml]);
            try testing.expectEqualSlices(u8, &t2, &t1);
        }
    }
    try testing.expectEqual(@as(usize, 1), powersFor(0, 0));
    try testing.expectEqual(@as(usize, 4), powersFor(17, 3)); // one group: 2 + 1 + 1
    try testing.expectEqual(@as(usize, 8), powersFor(5, 96)); // the largest short one
    try testing.expectEqual(@as(usize, 8), powersFor(5, 97)); // not short: 7 + 1
    try testing.expectEqual(@as(usize, 8), powersFor(0, 1 << 20));
}

test "every single-bit change of tag, ciphertext or AD is refused, and the output zeroed" {
    var prng = std.Random.DefaultPrng.init(0x7a3);
    const rnd = prng.random();
    inline for (.{ Aes128Gcm, Aes256Gcm }) |Gcm| {
        for ([_]usize{ 0, 1, 17, 130, 300 }) |ml| {
            var key: [Gcm.key_length]u8 = undefined;
            var iv: [12]u8 = undefined;
            var ad: [20]u8 = undefined;
            var m: [300]u8 = undefined;
            var c: [300]u8 = undefined;
            var out: [300]u8 = undefined;
            rnd.bytes(&key);
            rnd.bytes(&iv);
            rnd.bytes(&ad);
            rnd.bytes(&m);
            var t: [16]u8 = undefined;
            for (all_backends) |b| {
                var ctx = Gcm.initWith(b, key) orelse continue;
                defer ctx.wipe();
                ctx.encrypt(c[0..ml], &t, m[0..ml], &ad, iv);
                for (0..8 * (16 + ml + ad.len)) |bit| {
                    var tt = t;
                    var cc = c;
                    var aa = ad;
                    const byte = bit / 8;
                    const mask = @as(u8, 1) << @intCast(bit % 8);
                    if (byte < 16) tt[byte] ^= mask else if (byte < 16 + ml) cc[byte - 16] ^= mask else aa[byte - 16 - ml] ^= mask;
                    @memset(&out, 0x5a);
                    try testing.expectError(error.AuthenticationFailed, ctx.decrypt(out[0..ml], cc[0..ml], tt, &aa, iv));
                    for (out[0..ml]) |x| try testing.expectEqual(@as(u8, 0), x);
                    if (bit % 97 == 0) {
                        @memset(&out, 0x5a);
                        try testing.expectError(error.AuthenticationFailed, Gcm.decrypt(out[0..ml], cc[0..ml], tt, &aa, iv, key));
                        for (out[0..ml]) |x| try testing.expectEqual(@as(u8, 0), x);
                    }
                }
                // A wrong nonce too.
                var iv2 = iv;
                iv2[11] ^= 1;
                try testing.expectError(error.AuthenticationFailed, ctx.decrypt(out[0..ml], c[0..ml], t, &ad, iv2));
                try ctx.decrypt(out[0..ml], c[0..ml], t, &ad, iv);
                try testing.expectEqualSlices(u8, m[0..ml], out[0..ml]);
            }
        }
    }
}

test "the 32-bit counter wraps modulo 2^32 and leaves the nonce bits alone (inc32)" {
    // `x86_asm` first: comptime-false, it keeps the kernel below out of builds
    // that cannot compile it (another arch, the self-hosted backend on a
    // baseline CPU); `available` alone is a run-time check.
    if (!x86_asm or !available(.aesni)) return error.SkipZigTest;
    // Not reachable through the API — a 96-bit nonce starts the counter at
    // 2 and the length bound stops it at 2^32 − 1 — so the kernel is driven
    // directly from counters just below the wrap, through a full stitched
    // batch and the tail, against a CTR reference built on std's AES.
    var prng = std.Random.DefaultPrng.init(0xc0de);
    const rnd = prng.random();
    inline for (.{ 128, 256 }) |bits| {
        const Ni = NiKey(bits);
        const StdAes = if (bits == 128) crypto.core.aes.Aes128 else crypto.core.aes.Aes256;
        var key: [bits / 8]u8 = undefined;
        rnd.bytes(&key);
        const k = Ni.init(key, 8);
        const aes = StdAes.initEnc(key);
        var nonce: [12]u8 = undefined;
        rnd.bytes(&nonce);
        for ([_]u32{ 0xffff_fff0, 0xffff_fff9, 0xffff_ffff, 0xffff_fffe }) |start| {
            for ([_]usize{ 16, 100, 128, 256, 300, 520 }) |len| {
                var m: [520]u8 = undefined;
                var c: [520]u8 = undefined;
                var want: [520]u8 = undefined;
                rnd.bytes(&m);
                var blk: [16]u8 = undefined;
                blk[0..12].* = nonce;
                var ctr = start;
                var i: usize = 0;
                while (i < len) : (i += 16) {
                    mem.writeInt(u32, blk[12..16], ctr, .big);
                    var ks: [16]u8 = undefined;
                    aes.encrypt(&ks, &blk);
                    const n = @min(16, len - i);
                    for (want[i..][0..n], m[i..][0..n], ks[0..n]) |*w, x, y| w.* = x ^ y;
                    ctr +%= 1;
                }
                mem.writeInt(u32, blk[12..16], start, .big);
                const ctr_v = bswap(load(&blk));
                _ = k.sealBody(ctr_v, zero_v, c[0..len], m[0..len], "", zero_v);
                try testing.expectEqualSlices(u8, want[0..len], c[0..len]);
                var back: [520]u8 = undefined;
                _ = k.openBody(ctr_v, zero_v, back[0..len], c[0..len], "", zero_v);
                try testing.expectEqualSlices(u8, m[0..len], back[0..len]);
            }
        }
    }
    // And the increment itself, lane by lane.
    const before: V = @bitCast(@Vector(4, u32){ 0xffff_fffe, 0x1111_1111, 0x2222_2222, 0x3333_3333 });
    const after: @Vector(4, u32) = @bitCast(ctrAdd(before, 3));
    try testing.expectEqual(@Vector(4, u32){ 1, 0x1111_1111, 0x2222_2222, 0x3333_3333 }, after);
}

test "the x86 key expansion and GHASH multiply agree with std" {
    if (!x86_asm or !available(.aesni)) return error.SkipZigTest; // `x86_asm`: see the inc32 test
    var prng = std.Random.DefaultPrng.init(4);
    const rnd = prng.random();
    for (0..50) |_| {
        inline for (.{ 128, 256 }) |bits| {
            const StdAes = if (bits == 128) crypto.core.aes.Aes128 else crypto.core.aes.Aes256;
            var key: [bits / 8]u8 = undefined;
            rnd.bytes(&key);
            const k = NiKey(bits).init(key, 8);
            var blk: [16]u8 = undefined;
            rnd.bytes(&blk);
            var want: [16]u8 = undefined;
            StdAes.initEnc(key).encrypt(&want, &blk);
            var got: [16]u8 = undefined;
            store(&got, k.encBlock(load(&blk)));
            try testing.expectEqualSlices(u8, &want, &got);
            // GHASH of 1…20 blocks from our powers against std's Ghash.
            var h: [16]u8 = undefined;
            StdAes.initEnc(key).encrypt(&h, &@as([16]u8, @splat(0)));
            var data: [320]u8 = undefined;
            rnd.bytes(&data);
            for (1..21) |nb| {
                var st = Ghash.init(&h);
                st.update(data[0 .. 16 * nb]);
                var w: [16]u8 = undefined;
                st.final(&w);
                var g: [16]u8 = undefined;
                store(&g, bswap(ghashBytes(&k.h, zero_v, data[0 .. 16 * nb])));
                try testing.expectEqualSlices(u8, &w, &g);
            }
        }
    }
}

test "wipe zeroes the whole context" {
    for (all_backends) |b| {
        var ctx = Aes256Gcm.initWith(b, @splat(0x42)) orelse continue;
        const bytes = mem.asBytes(&ctx);
        try testing.expect(mem.indexOfNone(u8, bytes, &.{0}) != null); // not vacuous
        ctx.wipe();
        for (bytes) |x| try testing.expectEqual(@as(u8, 0), x);
    }
}

test "backend picks AES-NI when the CPU has it" {
    const b = backend();
    try testing.expect(available(b));
    try testing.expect(available(.generic));
    if (x86_asm) {
        try testing.expectEqual(if (cpuidAesni()) Backend.aesni else Backend.generic, b);
    } else {
        try testing.expectEqual(Backend.generic, b);
        try testing.expect(!available(.aesni));
        try testing.expectEqual(@as(?Aes128Gcm.Context, null), Aes128Gcm.initWith(.aesni, @splat(0)));
    }
    // A context is per key and per direction of a connection, so its size
    // is per-connection memory: round keys + H..H^8, or the AES schedule + H.
    try testing.expect(@sizeOf(Aes128Gcm.Context) <= 320);
    try testing.expect(@sizeOf(Aes256Gcm.Context) <= 384);
    // std's constants, so the type drops in where std's was.
    try testing.expectEqual(crypto.aead.aes_gcm.Aes256Gcm.key_length, Aes256Gcm.key_length);
    try testing.expectEqual(crypto.aead.aes_gcm.Aes128Gcm.nonce_length, Aes128Gcm.nonce_length);
    try testing.expectEqual(crypto.aead.aes_gcm.Aes128Gcm.tag_length, Aes128Gcm.tag_length);
}

test "fuzz: every backend agrees with std on arbitrary key, nonce, AD and message" {
    try testing.fuzz({}, fuzzAgree, .{});
}

var fuzz_buf: [3 * 1100]u8 = undefined;

fn fuzzAgree(_: void, smith: *std.testing.Smith) !void {
    var key: [32]u8 = undefined;
    var iv: [12]u8 = undefined;
    var ad: [80]u8 = undefined;
    smith.bytes(&key);
    smith.bytes(&iv);
    const ad_len = smith.slice(&ad);
    const m_len = smith.slice(fuzz_buf[0..1100]);
    const m = fuzz_buf[0..m_len];
    const c = fuzz_buf[1100..][0..m_len];
    const d = fuzz_buf[2200..][0..m_len];
    inline for (.{ Aes128Gcm, Aes256Gcm }) |Gcm| {
        const Std = if (Gcm.key_length == 16) crypto.aead.aes_gcm.Aes128Gcm else crypto.aead.aes_gcm.Aes256Gcm;
        const k = key[0..Gcm.key_length].*;
        var want_t: [16]u8 = undefined;
        Std.encrypt(d, &want_t, m, ad[0..ad_len], iv, k);
        for (all_backends) |b| {
            var ctx = Gcm.initWith(b, k) orelse continue;
            var t: [16]u8 = undefined;
            ctx.encrypt(c, &t, m, ad[0..ad_len], iv);
            try testing.expectEqualSlices(u8, d, c);
            try testing.expectEqualSlices(u8, &want_t, &t);
            // Arbitrary bytes as a tag: accepted exactly when std accepts.
            var forged: [16]u8 = undefined;
            smith.bytes(&forged);
            const ok = if (ctx.decrypt(c, d, forged, ad[0..ad_len], iv)) true else |_| false;
            try testing.expectEqual(mem.eql(u8, &forged, &want_t), ok);
        }
    }
}

test {
    _ = @import("stackprobe_test.zig");
}
