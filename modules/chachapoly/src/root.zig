// SPDX-License-Identifier: MIT

//! chachapoly — SIMD-accelerated ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! A performance-specialised reimplementation of the ChaCha20 stream cipher and
//! the ChaCha20-Poly1305 AEAD that `std.crypto` already ships. It exists **only**
//! for throughput: `std.crypto.stream.chacha` vectorises *within* one block (the
//! diagonal / `@shuffle` layout) but gates its AVX2/AVX-512 lanes behind
//! `builtin.cpu.has(.x86, .avx2)`, so at the default `baseline` x86-64 target it
//! collapses to a single 128-bit lane (degree 1) and runs ~3.9x slower than
//! OpenSSL's AVX2 ChaCha (measured: std 478 MB/s vs OpenSSL 1852 MB/s at 8 KiB).
//!
//! This module instead uses the **block-parallel (transpose) layout**: each of
//! the 16 ChaCha state words is held in a `@Vector(N, u32)` spanning `N`
//! consecutive counter blocks, so a quarter-round is `N`-way data-parallel with
//! no in-block shuffles. With `N = 8` a `@Vector(8, u32)` lowers to 256-bit AVX2
//! when the target enables it (`-Dcpu=native` / any AVX2 target), recovering most
//! of the gap; on `baseline` it lowers to paired SSE2 and is still correct.
//!
//! **Hybrid at both levels — short inputs are std's code.** A block-parallel
//! engine has no shape smaller than a whole group, and a group's cost is flat:
//! ~220 ns whether it emits 65 bytes or 512. Below that it loses to std, which
//! vectorises *within* a block and so has a cheap single-block shape. Two
//! measured thresholds keep this module off the ground it does not own:
//! `delegate_max_bytes` (64 B — one ChaCha block) hands short cipher runs to
//! `std.crypto.stream.chacha`, and `aead_delegate_max` (128 B of message + AD)
//! hands the whole short AEAD to `std.crypto.aead.chacha_poly`. This mirrors
//! what `poly1305.zig` already did internally, and it is why the module now
//! wins or ties at EVERY length instead of losing 0.80-0.95x below 144 bytes.
//! Both branches are on public lengths only — never on key or plaintext.
//!
//! **Dedup note.** `std` *has* ChaCha20-Poly1305 (`std.crypto.aead.chacha_poly`).
//! This is a deliberate performance-specialised duplicate, justified by the
//! measured 3.9x and the data-plane AEAD-throughput case (WireGuard per-packet,
//! TLS/Noise bulk). It is **byte-exact** to std and to RFC 8439: the SIMD ChaCha
//! is anchored against the RFC 8439 KATs *and* differentially against
//! `std.crypto.aead.chacha_poly.ChaCha20Poly1305` (the oracle) over every
//! block-boundary edge length.
//!
//! The Poly1305 MAC is **lane-parallel** — see `poly1305.zig`, which holds the
//! full design note. Short version: `L` blocks per multiply in a 5×26-bit limb
//! layout, `L` comptime-selected from the target (AVX2 → 4), hybridised with
//! `std.crypto.onetimeauth.Poly1305` as the serial core so that inputs below the
//! break-even size run std's code and cannot regress.
//!
//! **The XOR is fused.** `ChaCha20.xor` does not materialise the keystream: a
//! block group is transposed straight out of the `@Vector` state into 64-byte
//! vectors, XORed against unaligned loads of the input, and stored. The previous
//! shape — stage into a `[64 * N]u8`, then `out[j] = in[j] ^ ks[j]` — cost more
//! than the extra copy suggests: LLVM would not vectorise that loop at all
//! (`out` may alias `in`) and emitted one `movzbl`/`xor`/`mov` **per byte**.
//! Fusing took `xor` from 1102 to 2356 MB/s and the AEAD from 845 to 1394 MB/s
//! at 8 KiB, and 542 -> 1088 MB/s for a 1420-byte WireGuard-sized packet
//! (i7-7920HQ, AVX2, ReleaseFast). The MAC at ~3.9 GB/s and the cipher at
//! ~2.4 GB/s now compose to almost exactly the measured AEAD rate, so neither
//! side has slack left; going further means a wider group (AVX-512) or
//! interleaving the two, not another local fix.
//!
//! The sub-group tail generates one *whole* wide group and discards the unused
//! blocks: a wide group costs about what a single scalar block costs, so this
//! is a win for any tail longer than one block (it is most of the 1420-byte
//! gain), and a tail of one block or less goes to std instead. Only that tail
//! still stages through a stack buffer.
//!
//! **Constant-time.** ChaCha and Poly1305 are inherently constant-time — only
//! add / xor / rotate / (Poly1305) multiply / mask, no secret-indexed memory and
//! no data-dependent branches. The `@Vector` ops preserve this, and the MAC's
//! lane count is a comptime constant rather than a runtime CPU dispatch. Tag
//! comparison uses `std.crypto.timing_safe.eql`. The delegation thresholds add
//! *runtime* branches, but only on message and AD **lengths**, which are
//! public — a packet's size is on the wire before any of it is authenticated.
//! A branch on anything secret would be a timing oracle; a branch on a length
//! is not, and none may be added.
//!
//! API mirrors `std.crypto.stream.chacha.ChaCha20IETF` and
//! `std.crypto.aead.chacha_poly.ChaCha20Poly1305` so consumers can swap it in.

const std = @import("std");
const mem = std.mem;
const math = std.math;
const poly1305 = @import("poly1305.zig");
/// Lane-parallel Poly1305 (see `poly1305.zig`); falls back to
/// `std.crypto.onetimeauth.Poly1305` at comptime on targets without a usable
/// wide SIMD integer multiply.
pub const Poly1305 = poly1305.Poly1305;
const AuthenticationError = std.crypto.errors.AuthenticationError;

/// std's ChaCha20 and ChaCha20-Poly1305. These are **both** the oracle the
/// tests below differentiate against **and** the implementation this module
/// runs on short inputs — see `delegate_max_bytes` and `aead_delegate_max`.
/// One name for both roles on purpose: "byte-identical to std" is the module's
/// contract, and on the short path it holds because the code *is* std's.
const StdChaCha = std.crypto.stream.chacha.ChaCha20IETF;
const StdAead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec, // pure computation, no I/O
    .concurrency = .reentrant, // no shared state
    .model_after = "RFC 8439 (ChaCha20-Poly1305); block-parallel @Vector transpose layout after the vectorised std.crypto.stream.chacha; lane-parallel 5x26-bit-limb Poly1305 (r^L powers) hybridised with std.crypto.onetimeauth.Poly1305 as the serial core",
    .deps = .{}, // std only
};

// ── ChaCha20 (IETF, 96-bit nonce, 32-bit counter) ────────────────────────────

/// Number of blocks processed in parallel in the wide path. `@Vector(8, u32)`
/// lowers to 256-bit AVX2 on targets that enable it; to paired SSE2 otherwise.
const wide = 8;

/// Runs of at most this many bytes are handed to `StdChaCha` instead of being
/// generated here. 64 = one ChaCha block: below a whole block this engine has
/// no cheaper shape than a whole block, and std's does.
///
/// **MEASURED, not guessed** — i7-7920HQ, AVX2, ReleaseFast, `-Dcpu=native`,
/// from the `chacha20 xor by size` table in `bench.zig` (ns per call, minimum
/// of 5 runs; re-derive by rerunning it):
///
/// ```
///  BEFORE   16 B   32 B   48 B   64 B    80 B    96 B   144 B   512 B
///    ours  138.8  131.0  139.3  131.6   230.5   221.1   230.9   217.4
///     std  102.9  108.8  115.6  135.9   232.0   239.3   283.6   726.6
///   ratio   0.74x  0.83x  0.83x  1.03x   1.01x   1.08x   1.23x   3.34x
///
///  AFTER (this constant in place)
///   ratio   1.00x  1.01x  1.00x  1.01x   1.05x   1.14x   1.25x   3.22x
/// ```
///
/// The *shape* is the point, not the individual numbers. Our cost is flat in
/// the length — a partial block costs a whole block, and a sub-group tail
/// costs a whole 8-block group — while std's rises with it. So there is
/// exactly one crossover and it sits at one block: under 64 bytes we computed
/// a full block-parallel block that std's in-block-vectorised core does in
/// ~25% less time, and from 64 bytes up the wide group is ahead and pulls away
/// (3.2x by 512 B). Anything shorter than a block was pure loss for us.
///
/// This is the same hybrid the Poly1305 sibling already uses (`poly1305.zig`,
/// `wide_min_groups`): keep std for the region where std is faster, rather
/// than ship a documented regression.
///
/// **One length still loses: exactly 128 bytes (0.84x).** It is not a trend
/// and not ours — with AVX2, std runs exactly two blocks as a single degree-2
/// pass with no partial-block tail, the cheapest shape std has; at 129 bytes
/// std is back to 1.25x behind us, and at 65-120 we are already 1.03-1.14x
/// ahead. Raising this constant to cover 128 would hand back every one of
/// those wins to buy one size, so it stays at 64 and the loss is recorded here
/// rather than rounded away. It does not reach the AEAD: a 128-byte AEAD call
/// is inside `aead_delegate_max` and runs std end to end.
const delegate_max_bytes = 64;

// ── path witness (test builds only) ──────────────────────────────────────────
//
// A threshold bug is **byte-invisible**. Both engines are correct and produce
// identical output, so a reversed comparison — short packets taking the wide
// path, long ones taking std — passes every KAT, every differential against
// std, every in-place and unaligned sweep and every fuzz case in this file. It
// is a pure performance property, and the only thing that would notice is a
// benchmark nobody runs in CI.
//
// So record which engine each call took, and let a test assert it. This is the
// ONLY guard the thresholds have; without it they are unguarded, not
// under-guarded.
//
// `is_test` is a comptime constant, so outside a test build `Path` is `void`,
// every `note` below is a store to a zero-sized value, and none of it reaches
// the object file. It is not a runtime dispatch flag and non-test code must
// never read it. It also means the module's `.concurrency = .reentrant` claim
// still holds for everything that ships — the mutable state exists only in a
// test binary, where these tests are single-threaded.

const builtin = @import("builtin");

/// Which engine a call used: std's (short input) or this module's wide one.
pub const Path = enum { std_delegated, wide };

const Witness = if (builtin.is_test) Path else void;
const witness_init: Witness = if (builtin.is_test) .wide else {};

/// Engine taken by the last `ChaCha20.xor` / `ChaCha20.stream` call. For a call
/// long enough to run whole wide groups, this is the engine that handled the
/// TAIL, so it also pins the tail branch's direction.
pub var chacha_path: Witness = witness_init;
/// Engine taken by the last `ChaCha20Poly1305.encrypt` / `.decrypt` call.
pub var aead_path: Witness = witness_init;

inline fn note(w: *Witness, p: Path) void {
    if (builtin.is_test) w.* = p;
}

const native_endian = @import("builtin").cpu.arch.endian();

const sigma = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 }; // "expand 32-byte k"

fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    inline for (0..8) |i| k[i] = mem.readInt(u32, key[i * 4 ..][0..4], .little);
    return k;
}

fn nonceToWords(nonce: [12]u8) [3]u32 {
    return .{
        mem.readInt(u32, nonce[0..4], .little),
        mem.readInt(u32, nonce[4..8], .little),
        mem.readInt(u32, nonce[8..12], .little),
    };
}

/// Compute the ChaCha20 state for `N` consecutive blocks starting at `counter`
/// (block j uses counter `counter +% j`), returning the 16 post-`+= s` state
/// words in the block-parallel **transpose layout**: word i of every one of the
/// N blocks lives in lane i..N of `x[i]`. The words are NOT yet in memory order
/// — `blockWords` does that transpose, and it is the only place that may.
fn chachaCore(comptime N: usize, k: [8]u32, counter: u32, n: [3]u32) [16]@Vector(N, u32) {
    const V = @Vector(N, u32);
    const iota: V = comptime blk: {
        var a: [N]u32 = undefined;
        for (0..N) |j| a[j] = j;
        break :blk a;
    };
    const splat = struct {
        inline fn f(x: u32) V {
            return @splat(x);
        }
    }.f;

    const s = [16]V{
        splat(sigma[0]),        splat(sigma[1]), splat(sigma[2]), splat(sigma[3]),
        splat(k[0]),            splat(k[1]),     splat(k[2]),     splat(k[3]),
        splat(k[4]),            splat(k[5]),     splat(k[6]),     splat(k[7]),
        splat(counter) +% iota, splat(n[0]),     splat(n[1]),     splat(n[2]),
    };

    var x = s;
    comptime var round: usize = 0;
    inline while (round < 10) : (round += 1) {
        quarterRound(V, &x, 0, 4, 8, 12);
        quarterRound(V, &x, 1, 5, 9, 13);
        quarterRound(V, &x, 2, 6, 10, 14);
        quarterRound(V, &x, 3, 7, 11, 15);
        quarterRound(V, &x, 0, 5, 10, 15);
        quarterRound(V, &x, 1, 6, 11, 12);
        quarterRound(V, &x, 2, 7, 8, 13);
        quarterRound(V, &x, 3, 4, 9, 14);
    }
    inline for (0..16) |i| x[i] +%= s[i];
    return x;
}

/// The transpose. Gather block `j`'s 16 words out of the word-major state into
/// one `@Vector(16, u32)` in memory order, byte-swapped so that a `@bitCast` to
/// `[64]u8` is the little-endian keystream block RFC 8439 specifies.
///
/// Every consumer of the core goes through here, so there is exactly one place
/// that knows the lane layout. LLVM recognises the lane-extract pattern and
/// lowers it to a shuffle network (verified in the disassembly), not to 16
/// scalar extracts.
inline fn blockWords(comptime N: usize, x: [16]@Vector(N, u32), comptime j: usize) @Vector(16, u32) {
    var w: @Vector(16, u32) = undefined;
    inline for (0..16) |i| w[i] = x[i][j];
    // comptime branch on target endianness — no runtime cost, no secret input.
    return if (native_endian == .little) w else @byteSwap(w);
}

/// Fill `ks` with the keystream for `N` blocks starting at `counter`.
fn keystream(comptime N: usize, ks: *[64 * N]u8, k: [8]u32, counter: u32, n: [3]u32) void {
    const x = chachaCore(N, k, counter, n);
    inline for (0..N) |j| {
        ks[64 * j ..][0..64].* = @bitCast(blockWords(N, x, j));
    }
}

/// **Fused** keystream-and-XOR for a whole group of `N` blocks: the keystream
/// never becomes bytes in memory. Each block is transposed straight into a
/// 64-byte vector, XORed against an unaligned load of `in`, and stored to `out`
/// — no `[64 * N]u8` staging buffer and no bytewise loop (the bytewise loop is
/// what LLVM refused to vectorise, because `out` may alias `in`).
///
/// `out` and `in` may be the same pointer (in-place): every byte of a block is
/// read before any byte of that block is written.
inline fn xorBlocks(comptime N: usize, out: *[64 * N]u8, in: *const [64 * N]u8, x: [16]@Vector(N, u32)) void {
    const Block = @Vector(64, u8);
    inline for (0..N) |j| {
        const ks: Block = @bitCast(blockWords(N, x, j));
        // Unaligned load/store: callers hand us arbitrary `[]u8` slices, so
        // nothing may be assumed about alignment. `[64]u8` has alignment 1.
        const src: Block = in[64 * j ..][0..64].*;
        out[64 * j ..][0..64].* = @as([64]u8, src ^ ks);
    }
}

/// XOR `ks` into `in` -> `out` for a partial (sub-group) run, in vector-width
/// chunks with a bytewise remainder. Both loop bounds are functions of the
/// message length, which is public; nothing here depends on key or plaintext.
inline fn xorTail(out: []u8, in: []const u8, ks: []const u8) void {
    const Chunk = @Vector(32, u8);
    var j: usize = 0;
    while (j + 32 <= ks.len) : (j += 32) {
        const a: Chunk = in[j..][0..32].*;
        const b: Chunk = ks[j..][0..32].*;
        out[j..][0..32].* = @as([32]u8, a ^ b);
    }
    while (j < ks.len) : (j += 1) out[j] = in[j] ^ ks[j];
}

inline fn quarterRound(comptime V: type, x: *[16]V, a: usize, b: usize, c: usize, d: usize) void {
    x[a] +%= x[b];
    x[d] = math.rotl(V, x[d] ^ x[a], @as(u32, 16));
    x[c] +%= x[d];
    x[b] = math.rotl(V, x[b] ^ x[c], @as(u32, 12));
    x[a] +%= x[b];
    x[d] = math.rotl(V, x[d] ^ x[a], @as(u32, 8));
    x[c] +%= x[d];
    x[b] = math.rotl(V, x[b] ^ x[c], @as(u32, 7));
}

/// IETF ChaCha20 stream cipher — 32-byte key, 12-byte nonce, 32-bit counter.
/// API-compatible with `std.crypto.stream.chacha.ChaCha20IETF`.
pub const ChaCha20 = struct {
    pub const key_length = 32;
    pub const nonce_length = 12;
    pub const block_length = 64;

    /// XOR the ChaCha20 keystream (starting at block `counter`) into `in`,
    /// writing to `out`. `out.len == in.len`. NOT authenticated on its own.
    ///
    /// `out` and `in` must be either the **same** slice (in-place, which is what
    /// the AEAD and every network consumer does) or **disjoint**. Partially
    /// overlapping slices are not supported — the fused path reads a whole
    /// 64-byte block before writing it, as std's block-buffered `xor` does.
    pub fn xor(out: []u8, in: []const u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
        std.debug.assert(out.len == in.len);
        // RFC 8439 §2.3: the 32-bit block counter must not wrap. A wrap restarts
        // the keystream and reuses it (two-time-pad), silently destroying
        // confidentiality. Reject in safe builds — matches the assert in
        // std.crypto.stream.chacha; a caller streaming past the counter space
        // must re-key or advance the nonce.
        std.debug.assert(@as(u64, (in.len + 63) / 64) + counter <= (@as(u64, 1) << 32));
        // Short whole call -> std, before anything else happens. See
        // `delegate_max_bytes`. This is a strict SUBSET of the tail branch at
        // the bottom (if it fires, the group loop cannot run and `rem` would
        // equal `in.len`), so the two comparisons cannot disagree about which
        // engine a given length gets; it exists only to return before the
        // function builds the wide path's 512-byte stack frame and splits the
        // key/nonce into words. Measured worth ~6 ns of a ~108 ns call — the
        // difference between 0.95x and 1.01x against std at 16 bytes.
        //
        // Branch on the message LENGTH, which is public (it is on the wire
        // before a byte is decrypted). Never on key or plaintext.
        if (in.len <= delegate_max_bytes) {
            note(&chacha_path, .std_delegated);
            return StdChaCha.xor(out, in, counter, key, nonce);
        }
        note(&chacha_path, .wide);

        const k = keyToWords(key);
        const n = nonceToWords(nonce);
        var ctr = counter;
        var i: usize = 0;

        // Whole groups: fused, no staging buffer.
        while (i + 64 * wide <= in.len) : (i += 64 * wide) {
            const x = chachaCore(wide, k, ctr, n);
            xorBlocks(wide, out[i..][0 .. 64 * wide], in[i..][0 .. 64 * wide], x);
            ctr +%= wide;
        }

        // Tail: fewer than `wide` whole blocks left, so the group cannot be
        // XORed in place and the keystream is staged (at most 512 bytes, once
        // per call). Both branches below are on the *message length*, which is
        // public — a ChaCha20 message length is visible on the wire before a
        // byte of it is decrypted. NOTHING here may become a branch on key or
        // plaintext; that would be a timing oracle, whereas this is not.
        //
        // When `in.len` is itself below the threshold the loop above never
        // ran, so `rem == in.len` and this same branch is the whole call —
        // which is the point. One comparison covers both "short message" and
        // "short tail after the wide groups".
        const rem = in.len - i;
        if (rem > delegate_max_bytes) {
            // A wide group costs about the same as ONE scalar block — same
            // instruction count, `wide` times the width — so generating all
            // `wide` blocks and discarding the unused suffix beats any
            // narrower loop as soon as more than one block is left (measured:
            // flat ~220 ns for every tail from 65 to 512 bytes). The discarded
            // lanes may carry counters past 2^32-1 (`+% iota`); those bytes are
            // never emitted, so the anti-wrap guarantee above is unaffected.
            var ks: [64 * wide]u8 = undefined;
            keystream(wide, &ks, k, ctr, n);
            xorTail(out[i..], in[i..], ks[0..rem]);
        } else if (rem > 0) {
            // Under one block: std wins, so std runs it. See
            // `delegate_max_bytes` for the measurement. This is what makes a
            // WireGuard keepalive, a 40-byte tunnelled ACK, and the AEAD's
            // 32-byte Poly1305-key derivation (paid by EVERY AEAD call, at
            // every length) cost what std costs instead of ~25% more.
            note(&chacha_path, .std_delegated);
            StdChaCha.xor(out[i..], in[i..], ctr, key, nonce);
        }
    }

    /// Write the raw ChaCha20 keystream (starting at block `counter`) into `out`.
    pub fn stream(out: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
        // See `xor`: the 32-bit block counter must not wrap (keystream reuse).
        std.debug.assert(@as(u64, (out.len + 63) / 64) + counter <= (@as(u64, 1) << 32));
        // Short whole call -> std; see the matching note in `xor`.
        if (out.len <= delegate_max_bytes) {
            note(&chacha_path, .std_delegated);
            return StdChaCha.stream(out, counter, key, nonce);
        }
        note(&chacha_path, .wide);

        const k = keyToWords(key);
        const n = nonceToWords(nonce);
        var ctr = counter;
        var i: usize = 0;

        while (i + 64 * wide <= out.len) : (i += 64 * wide) {
            keystream(wide, out[i..][0 .. 64 * wide], k, ctr, n);
            ctr +%= wide;
        }
        // Tail — see the matching note in `xor`, which this mirrors exactly:
        // one wide group with the unused blocks discarded above the threshold,
        // std below it. Branch on the output length only, which is public.
        const rem = out.len - i;
        if (rem > delegate_max_bytes) {
            var ks: [64 * wide]u8 = undefined;
            keystream(wide, &ks, k, ctr, n);
            @memcpy(out[i..], ks[0..rem]);
        } else if (rem > 0) {
            note(&chacha_path, .std_delegated);
            StdChaCha.stream(out[i..], ctr, key, nonce);
        }
    }
};

// ── ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) ───────────────────────────────────

/// Total input — message **plus** associated data — at or below which the
/// whole AEAD is handed to `StdAead`. Message + AD, not just the message,
/// because the MAC covers both while only the message goes through the cipher:
/// a 0-byte message with 1 KiB of AD is a long MAC and belongs on the wide
/// path, and a threshold on `m.len` alone would send it to std.
///
/// **MEASURED, not guessed** — i7-7920HQ, AVX2, ReleaseFast, `-Dcpu=native`,
/// from the `aead seal by size` / `aead open by size` tables in `bench.zig`
/// (ns per call, minimum of 5 runs), taken *after* `delegate_max_bytes` above
/// had already removed the cipher's short-run cost:
///
/// ```
///           64 B   80 B   96 B  112 B  128 B  144 B  160 B  192 B
///    ours  327.5  442.9  430.5  454.5  455.6  479.4  473.3  504.0
///     std  329.8  435.6  447.4  458.6  413.0  521.7  534.7  587.2
///   ratio   1.01x  0.98x  1.04x  1.01x  0.91x  1.09x  1.13x  1.16x
///
///  AFTER (this constant in place; <=128 is std's code, so 1.00x is exact and
///  the +/-1% is timer noise, not a difference)
///   ratio   0.99x  1.00x  1.00x  1.00x  1.01x  1.12x  1.15x  1.15x
/// ```
///
/// 128 is the last size at which std wins and 144 the first at which this
/// module wins by a margin worth having, so the threshold is 128 *inclusive*.
/// The dip at exactly 128 is not noise and not ours: with AVX2 std's ChaCha
/// runs 128 bytes as one 2-block pass with NO partial-block tail, which is the
/// cheapest shape it has. Below 144 the residual gap is only 2-5% and is not
/// the cipher any more (that was fixed by `delegate_max_bytes`) — it is this
/// module's own per-call overhead, chiefly a `Poly1305` state ~3x the size of
/// std's. Rather than shave that, delegate: below the threshold the code that
/// runs IS std's, so the parity is exact by construction instead of by tuning.
///
/// Note what is NOT here: the Poly1305 power table, which the original
/// diagnosis blamed. `poly1305.zig` already guards itself (`wide_min_groups`)
/// and stays on std's serial core below 176 bytes, so it contributes exactly
/// zero to the short-packet gap — confirmed by the `poly1305 by size` bench
/// rows reading 0.97-1.01x at 32/64/128 bytes.
///
/// Re-derive by rerunning the bench: the threshold is the last size whose
/// ratio is below 1.00x.
const aead_delegate_max = 128;

/// ChaCha20-Poly1305 AEAD, as designed for TLS/RFC 8439. Byte-for-byte
/// compatible with `std.crypto.aead.chacha_poly.ChaCha20Poly1305`.
pub const ChaCha20Poly1305 = struct {
    pub const tag_length = 16;
    pub const nonce_length = 12;
    pub const key_length = 32;

    /// Encrypt `m` into `c` (`c.len == m.len`) and write the auth tag to `tag`.
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
        std.debug.assert(c.len == m.len);

        // Short total -> run std's AEAD unchanged. See `aead_delegate_max`.
        // The branch is on the two LENGTHS, both of which are public: a
        // packet's size and its AD's size are visible to anyone on the path
        // before any of it is authenticated. Nothing secret may ever be added
        // to this condition — a branch on key or plaintext would be a timing
        // oracle, a branch on a length is not.
        if (m.len + ad.len <= aead_delegate_max) {
            note(&aead_path, .std_delegated);
            return StdAead.encrypt(c, tag, m, ad, npub, k);
        }
        note(&aead_path, .wide);

        var poly_key = [_]u8{0} ** 32;
        ChaCha20.xor(poly_key[0..], poly_key[0..], 0, k, npub);

        ChaCha20.xor(c[0..m.len], m, 1, k, npub);

        var mac = Poly1305.init(poly_key[0..]);
        mac.update(ad);
        pad16(&mac, ad.len);
        mac.update(c[0..m.len]);
        pad16(&mac, m.len);
        var lens: [16]u8 = undefined;
        mem.writeInt(u64, lens[0..8], ad.len, .little);
        mem.writeInt(u64, lens[8..16], m.len, .little);
        mac.update(lens[0..]);
        mac.final(tag);
    }

    /// Verify `tag` and decrypt `c` into `m` (`c.len == m.len`).
    /// On failure returns `error.AuthenticationFailed` and `m` is zeroed.
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
        std.debug.assert(c.len == m.len);

        // Short total -> std's AEAD. Same public-length branch as `encrypt`;
        // see `aead_delegate_max`.
        if (c.len + ad.len <= aead_delegate_max) {
            note(&aead_path, .std_delegated);
            StdAead.decrypt(m, c, tag, ad, npub, k) catch |e| {
                // The one place the delegation is NOT a straight hand-off.
                // std documents `m` as *undefined* after a rejection and
                // implements that as `@memset(m, undefined)`, which is a hint
                // ReleaseFast elides — so a caller's pre-loaded bytes survive.
                // This module documents `m` as ZEROED and a test asserts it
                // (see "decrypt zeroes the output buffer ... (audit F3)",
                // whose 25-byte message runs exactly this path). Carry the
                // stronger promise across the seam rather than quietly
                // weakening it for short messages.
                std.crypto.secureZero(u8, m);
                return e;
            };
            return;
        }
        note(&aead_path, .wide);

        var poly_key = [_]u8{0} ** 32;
        ChaCha20.xor(poly_key[0..], poly_key[0..], 0, k, npub);

        var mac = Poly1305.init(poly_key[0..]);
        mac.update(ad);
        pad16(&mac, ad.len);
        mac.update(c);
        pad16(&mac, c.len);
        var lens: [16]u8 = undefined;
        mem.writeInt(u64, lens[0..8], ad.len, .little);
        mem.writeInt(u64, lens[8..16], c.len, .little);
        mac.update(lens[0..]);
        var computed_tag: [16]u8 = undefined;
        mac.final(&computed_tag);

        if (!std.crypto.timing_safe.eql([tag_length]u8, computed_tag, tag)) {
            std.crypto.secureZero(u8, &computed_tag);
            // Honour the doc contract: actually zero `m` on auth failure. std uses
            // `@memset(m, undefined)` (a no-op hint elided in ReleaseFast); a
            // `secureZero` makes the "m is zeroed" promise true in every build and
            // clears any caller-preloaded bytes without leaking plaintext (which
            // this path never wrote — the keystream xor below is post-check).
            std.crypto.secureZero(u8, m);
            return error.AuthenticationFailed;
        }
        ChaCha20.xor(m[0..c.len], c, 1, k, npub);
    }
};

/// Poly1305 zero-padding to the next 16-byte boundary.
fn pad16(mac: *Poly1305, len: usize) void {
    if (len % 16 != 0) {
        const zeros = [_]u8{0} ** 16;
        mac.update(zeros[0 .. 16 - (len % 16)]);
    }
}

// ── tests: RFC 8439 known-answer vectors ─────────────────────────────────────

const testing = std.testing;

test {
    _ = @import("poly1305.zig");
    _ = @import("bench.zig");
}

// RFC 8439 §2.3.2 — ChaCha20 block function (counter = 1).
test "RFC 8439 §2.3.2 ChaCha20 block/keystream" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [_]u8{ 0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    const expected = [_]u8{
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };
    var out: [64]u8 = undefined;
    ChaCha20.stream(&out, 1, key, nonce);
    try testing.expectEqualSlices(u8, &expected, &out);
}

// RFC 8439 §2.4.2 — ChaCha20 encryption ("sunscreen"), counter = 1.
test "RFC 8439 §2.4.2 ChaCha20 encrypt (sunscreen)" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const expected = [_]u8{
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };
    var out: [114]u8 = undefined;
    ChaCha20.xor(&out, m, 1, key, nonce);
    try testing.expectEqualSlices(u8, &expected, &out);
    // round-trip
    var back: [114]u8 = undefined;
    ChaCha20.xor(&back, &out, 1, key, nonce);
    try testing.expectEqualSlices(u8, m, &back);
}

// RFC 8439 §2.5.2 — Poly1305 (documents the scalar std MAC we reuse).
test "RFC 8439 §2.5.2 Poly1305 tag" {
    const otk = [_]u8{
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    const msg = "Cryptographic Forum Research Group";
    const expected = [_]u8{
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };
    var tag: [16]u8 = undefined;
    Poly1305.create(&tag, msg, &otk);
    try testing.expectEqualSlices(u8, &expected, &tag);
}

// RFC 8439 §2.8.2 — AEAD ChaCha20-Poly1305 encrypt (ciphertext + tag).
test "RFC 8439 §2.8.2 AEAD encrypt + tag" {
    const key = [_]u8{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const nonce = [_]u8{ 0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    const ad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const expected_c = [_]u8{
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    };
    const expected_tag = [_]u8{
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };
    var c: [114]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&c, &tag, m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &expected_c, &c);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    var back: [114]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&back, &c, tag, &ad, nonce, key);
    try testing.expectEqualSlices(u8, m, &back);
}

// ── tests: differential vs std (the oracle), across block-boundary edges ──────

const edge_lens = [_]usize{ 0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1000, 4096 };

test "differential ChaCha20 stream vs std across edge lengths" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var ours: [4096]u8 = undefined;
    var theirs: [4096]u8 = undefined;
    for (edge_lens) |len| {
        for ([_]u32{ 0, 1, 1000 }) |ctr| {
            ChaCha20.stream(ours[0..len], ctr, key, nonce);
            @memset(theirs[0..len], 0);
            StdChaCha.stream(theirs[0..len], ctr, key, nonce);
            try testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
        }
    }
}

test "differential ChaCha20 xor vs std across edge lengths" {
    var prng = std.Random.DefaultPrng.init(0xBADF00D);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var msg: [4096]u8 = undefined;
    var ours: [4096]u8 = undefined;
    var theirs: [4096]u8 = undefined;
    rand.bytes(&msg);
    for (edge_lens) |len| {
        ChaCha20.xor(ours[0..len], msg[0..len], 1, key, nonce);
        StdChaCha.xor(theirs[0..len], msg[0..len], 1, key, nonce);
        try testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
    }
}

test "differential AEAD vs std: seal/open/tamper across edge lengths" {
    var prng = std.Random.DefaultPrng.init(0x5EED_1234);
    const rand = prng.random();

    var msg: [4096]u8 = undefined;
    var ad: [64]u8 = undefined;
    var ours_c: [4096]u8 = undefined;
    var std_c: [4096]u8 = undefined;
    var dec: [4096]u8 = undefined;

    for (edge_lens) |len| {
        var key: [32]u8 = undefined;
        var nonce: [12]u8 = undefined;
        rand.bytes(&key);
        rand.bytes(&nonce);
        rand.bytes(msg[0..len]);
        const ad_len = len % ad.len;
        rand.bytes(ad[0..ad_len]);

        var ours_tag: [16]u8 = undefined;
        var std_tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(ours_c[0..len], &ours_tag, msg[0..len], ad[0..ad_len], nonce, key);
        StdAead.encrypt(std_c[0..len], &std_tag, msg[0..len], ad[0..ad_len], nonce, key);

        // byte-exact ciphertext + tag vs the std oracle
        try testing.expectEqualSlices(u8, std_c[0..len], ours_c[0..len]);
        try testing.expectEqualSlices(u8, &std_tag, &ours_tag);

        // decrypt(encrypt) == identity
        try ChaCha20Poly1305.decrypt(dec[0..len], ours_c[0..len], ours_tag, ad[0..ad_len], nonce, key);
        try testing.expectEqualSlices(u8, msg[0..len], dec[0..len]);

        // cross-decrypt: our AEAD opens std's ciphertext and vice-versa
        try ChaCha20Poly1305.decrypt(dec[0..len], std_c[0..len], std_tag, ad[0..ad_len], nonce, key);
        try testing.expectEqualSlices(u8, msg[0..len], dec[0..len]);
        try StdAead.decrypt(dec[0..len], ours_c[0..len], ours_tag, ad[0..ad_len], nonce, key);
        try testing.expectEqualSlices(u8, msg[0..len], dec[0..len]);

        // tag tamper is rejected
        var bad_tag = ours_tag;
        bad_tag[0] +%= 1;
        try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(dec[0..len], ours_c[0..len], bad_tag, ad[0..ad_len], nonce, key));
        // ciphertext tamper is rejected (skip len==0: no ciphertext byte to flip)
        if (len > 0) {
            var bad_c = ours_c;
            bad_c[len - 1] +%= 1;
            try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(dec[0..len], bad_c[0..len], ours_tag, ad[0..ad_len], nonce, key));
        }
    }
}

test "differential AEAD vs std with LONG associated data" {
    // The sweep above derives `ad_len` from `len % 64`, so it never sends more
    // than 63 bytes of AD, and the threshold test below caps it at 129. Neither
    // reaches the MAC's own wide threshold (176 B at L = 4), so nothing else
    // here exercises the AEAD's real long-AD shape: the vector engine absorbs
    // the AD, `pad16` lands on the accumulator it just wrote back, and the
    // vector engine then absorbs the ciphertext. An AEAD open with a large AD
    // and a small ciphertext is an ordinary protocol shape, not a corner case.
    var prng = std.Random.DefaultPrng.init(0xA11CE);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var msg: [2100]u8 = undefined;
    var ad: [2100]u8 = undefined;
    rand.bytes(&msg);
    rand.bytes(&ad);
    var ours_c: [2100]u8 = undefined;
    var std_c: [2100]u8 = undefined;
    var dec: [2100]u8 = undefined;

    const lens = [_]usize{ 0, 1, 16, 127, 128, 129, 175, 176, 177, 191, 192, 193, 256, 384, 512, 1000, 1420, 2048, 2100 };
    for (lens) |ad_len| {
        for (lens) |m_len| {
            var ours_tag: [16]u8 = undefined;
            var std_tag: [16]u8 = undefined;
            ChaCha20Poly1305.encrypt(ours_c[0..m_len], &ours_tag, msg[0..m_len], ad[0..ad_len], nonce, key);
            StdAead.encrypt(std_c[0..m_len], &std_tag, msg[0..m_len], ad[0..ad_len], nonce, key);
            testing.expectEqualSlices(u8, std_c[0..m_len], ours_c[0..m_len]) catch |e| {
                std.debug.print("ct mismatch ad={d} m={d}\n", .{ ad_len, m_len });
                return e;
            };
            testing.expectEqualSlices(u8, &std_tag, &ours_tag) catch |e| {
                std.debug.print("tag mismatch ad={d} m={d}\n", .{ ad_len, m_len });
                return e;
            };
            try ChaCha20Poly1305.decrypt(dec[0..m_len], std_c[0..m_len], std_tag, ad[0..ad_len], nonce, key);
            try testing.expectEqualSlices(u8, msg[0..m_len], dec[0..m_len]);
        }
    }
}

// ── tests: the delegation seams ──────────────────────────────────────────────
//
// `delegate_max_bytes` and `aead_delegate_max` each introduce a seam where two
// engines must agree byte for byte. The sweeps elsewhere in this file cross
// both incidentally; these two tests cross them ON PURPOSE, one length at a
// time, so a future edit to either constant lands on a test that is obviously
// about it.

test "differential vs std across the AEAD delegation threshold" {
    // Every total length from `aead_delegate_max - 8` to `+ 8`, seal and open.
    // The threshold is on `m.len + ad.len`, not on `m.len`, so each total is
    // split several ways: an implementation that compared only the message
    // length would pass a message-only sweep and fail here.
    var prng = std.Random.DefaultPrng.init(0x7B5E_5401);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var msg: [256]u8 = undefined;
    var ad: [64]u8 = undefined;
    rand.bytes(&msg);
    rand.bytes(&ad);

    var ours_c: [256]u8 = undefined;
    var std_c: [256]u8 = undefined;
    var dec: [256]u8 = undefined;

    var total: usize = aead_delegate_max - 8;
    while (total <= aead_delegate_max + 8) : (total += 1) {
        for ([_]usize{ 0, 1, 15, 16, 17, 32 }) |ad_len| {
            if (ad_len > total) continue;
            const m_len = total - ad_len;

            var ours_tag: [16]u8 = undefined;
            var std_tag: [16]u8 = undefined;
            ChaCha20Poly1305.encrypt(ours_c[0..m_len], &ours_tag, msg[0..m_len], ad[0..ad_len], nonce, key);
            StdAead.encrypt(std_c[0..m_len], &std_tag, msg[0..m_len], ad[0..ad_len], nonce, key);

            testing.expectEqualSlices(u8, std_c[0..m_len], ours_c[0..m_len]) catch |e| {
                std.debug.print("seal mismatch: total={d} m={d} ad={d}\n", .{ total, m_len, ad_len });
                return e;
            };
            testing.expectEqualSlices(u8, &std_tag, &ours_tag) catch |e| {
                std.debug.print("tag mismatch: total={d} m={d} ad={d}\n", .{ total, m_len, ad_len });
                return e;
            };

            // open, both directions across the seam
            try ChaCha20Poly1305.decrypt(dec[0..m_len], std_c[0..m_len], std_tag, ad[0..ad_len], nonce, key);
            try testing.expectEqualSlices(u8, msg[0..m_len], dec[0..m_len]);
            try StdAead.decrypt(dec[0..m_len], ours_c[0..m_len], ours_tag, ad[0..ad_len], nonce, key);
            try testing.expectEqualSlices(u8, msg[0..m_len], dec[0..m_len]);

            // and a rejection still zeroes `m` on BOTH sides of the seam —
            // the delegated path has to re-add that promise by hand, because
            // std only leaves `m` undefined.
            var bad_tag = ours_tag;
            bad_tag[0] +%= 1;
            @memset(dec[0..m_len], 0xAA);
            try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(dec[0..m_len], ours_c[0..m_len], bad_tag, ad[0..ad_len], nonce, key));
            for (dec[0..m_len]) |b| try testing.expectEqual(@as(u8, 0), b);
        }
    }
}

test "differential vs std across the ChaCha20 delegation threshold" {
    // `delegate_max_bytes` is crossed twice by every long call: once as the
    // whole message length, once as the tail left after the wide groups. Both
    // are swept here — the second by adding a whole 512-byte group to each
    // length, which the plain 0..1024 sweep also covers but not by name.
    var prng = std.Random.DefaultPrng.init(0xC0DEC0DE);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var msg: [1024]u8 = undefined;
    rand.bytes(&msg);
    var ours: [1024]u8 = undefined;
    var theirs: [1024]u8 = undefined;

    var n: usize = delegate_max_bytes - 8;
    while (n <= delegate_max_bytes + 8) : (n += 1) {
        for ([_]usize{ 0, 64 * wide }) |base| {
            const len = base + n;
            for ([_]u32{ 0, 1, 7, 0xFFFF }) |ctr| {
                ChaCha20.xor(ours[0..len], msg[0..len], ctr, key, nonce);
                StdChaCha.xor(theirs[0..len], msg[0..len], ctr, key, nonce);
                testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]) catch |e| {
                    std.debug.print("xor mismatch at len={d} ctr={d}\n", .{ len, ctr });
                    return e;
                };
                ChaCha20.stream(ours[0..len], ctr, key, nonce);
                StdChaCha.stream(theirs[0..len], ctr, key, nonce);
                try testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
            }
        }
    }
}

// THE ONLY TEST THAT CAN FAIL ON A WRONG THRESHOLD.
//
// Everything else in this file compares bytes, and both engines produce the
// same bytes — so reversing either comparison, or moving either constant,
// leaves every KAT, every differential, every sweep and every fuzz case GREEN
// while destroying the property the thresholds exist for. That is the whole
// reason `chacha_path` / `aead_path` exist (see their note above).
//
// What this still cannot check, stated plainly because both holes were found
// by mutation and the second one is still open:
//
//   1. That the constants are the RIGHT numbers. They came from a measurement
//      on one host; only rerunning `bench.zig` can re-derive them. This test
//      pins the routing, not the tuning.
//      CORRECTED 2026-08-11. This note used to claim: "the case tables below
//      are written in terms of the CURRENT values, so CHANGING a constant
//      turns the suite red (the across-threshold differential aborts)". That
//      was FALSE, and measurably so: the tables reference the constants
//      SYMBOLICALLY (`.{ .m = aead_delegate_max, ... }`), so every case moves
//      with the constant and re-asserts whatever it now is. Mutation:
//      `aead_delegate_max` 128 -> 130 exited 0; `delegate_max_bytes` 64 -> 80
//      exited 0. The only thing that ever went red was a change big enough to
//      overrun the 256-byte buffer in the across-threshold differential —
//      a buffer bound, not a guard.
//      The fix is the LITERAL table added at the end of this test: it pins the
//      delivered numbers (64 and 128) and the routing they produce, so a
//      retune is red for the right reason. The symbolic tables above are kept
//      because they express the SHAPE — every comparison replayed against
//      every implementation of it — which is a different property and still
//      worth having. Re-deriving a threshold on another host now means editing
//      the literals too: that is the deliberate act the old note claimed, made
//      true.
//   2. The ENTRY fast path in `xor`/`stream`. Disabling it (`in.len <= 0`)
//      leaves every test green — correctly so, because it is not a routing
//      change: the tail branch still hands the run to std, so the witness
//      records the same engine and the bytes are unchanged. All that is lost
//      is the ~6 ns of wide-path frame setup the early return exists to skip
//      (measured: 0.95x vs 1.01x against std at 16 bytes). A redundant fast
//      path is invisible to a witness by construction — the only thing that
//      can see it is `bench.zig`'s `chacha20 xor by size` table.
//
// Everything that is a genuine mis-ROUTING is covered, verified by mutating
// each of the six comparison sites in turn and judging by exit code.
test "delegation thresholds route each length to the engine it was measured for" {
    // ── HOW THIS TEST IS BUILT, AND WHY ─────────────────────────────────────
    //
    // Both entry points below have TWO implementations of the same comparison
    // (`xor` and `stream`; `encrypt` and `decrypt`), and each comparison has
    // more than one way to be wrong. The first version of this test wrote the
    // assertions out by hand per entry point, and that is exactly how it grew
    // a hole: `decrypt` got a message-length pair and no AD-dominant one, so
    // `c.len + ad.len <= T` could be mutated to `c.len <= T` — dropping the AD
    // term on the side an attacker feeds — and the whole suite stayed green.
    // `stream` had the same hole for its tail branch: only `xor`'s tail was
    // ever asserted, so `stream`'s could be made to never delegate at all and
    // nothing noticed. Both were confirmed by mutation, both exited 0.
    //
    // So the cases live in TABLES that are replayed against every
    // implementation of the comparison. A case cannot be covered on one side
    // and forgotten on the other, because there is only one side.
    const key = [_]u8{0x21} ** 32;
    const nonce = [_]u8{0x43} ** 12;
    const grp = 64 * wide;
    var buf: [2 * grp]u8 = undefined;
    var out: [2 * grp]u8 = undefined;
    var dec: [2 * grp]u8 = undefined;
    var tag: [16]u8 = undefined;
    @memset(&buf, 0x5A);

    // ── ChaCha20. Replayed against `xor` AND `stream`. ──
    const CipherCase = struct { len: usize, want: Path, why: []const u8 };
    for ([_]CipherCase{
        .{ .len = 0, .want = .std_delegated, .why = "empty" },
        .{ .len = 1, .want = .std_delegated, .why = "one byte" },
        .{ .len = delegate_max_bytes, .want = .std_delegated, .why = "at the threshold" },
        .{ .len = delegate_max_bytes + 1, .want = .wide, .why = "one past it" },
        // The TAIL branch, which no short call can reach: a whole wide group
        // plus a tail on each side of the threshold. `chacha_path` records the
        // TAIL's engine, so these pin that branch independently of the entry
        // check — and they are what a "tail never delegates" mutation trips.
        .{ .len = grp, .want = .wide, .why = "exact group, no tail" },
        .{ .len = grp + 1, .want = .std_delegated, .why = "1-byte tail" },
        .{ .len = grp + delegate_max_bytes, .want = .std_delegated, .why = "tail at the threshold" },
        .{ .len = grp + delegate_max_bytes + 1, .want = .wide, .why = "tail one past it" },
    }) |c| {
        ChaCha20.xor(out[0..c.len], buf[0..c.len], 1, key, nonce);
        testing.expectEqual(c.want, chacha_path) catch |e| {
            std.debug.print("xor routed {d} B ({s}) to {s}\n", .{ c.len, c.why, @tagName(chacha_path) });
            return e;
        };
        ChaCha20.stream(out[0..c.len], 1, key, nonce);
        testing.expectEqual(c.want, chacha_path) catch |e| {
            std.debug.print("stream routed {d} B ({s}) to {s}\n", .{ c.len, c.why, @tagName(chacha_path) });
            return e;
        };
    }

    // ── AEAD. Replayed against `encrypt` AND `decrypt`. ──
    //
    // The threshold is on message + AD, so the table has to move the total
    // across it from BOTH terms. The `ad`-dominant rows are the load-bearing
    // ones: in every one of them the ciphertext alone stays at or below the
    // threshold, so an implementation that compared only `c.len`/`m.len` would
    // route them all to std and fail on the `.wide` rows. An AEAD open with a
    // tiny ciphertext and a large AD is an ordinary shape, not a corner case.
    const AeadCase = struct { m: usize, ad: usize, want: Path, why: []const u8 };
    for ([_]AeadCase{
        // the message moves the total
        .{ .m = aead_delegate_max, .ad = 0, .want = .std_delegated, .why = "msg at threshold" },
        .{ .m = aead_delegate_max + 1, .ad = 0, .want = .wide, .why = "msg one past" },
        // the AD moves the total, message pinned below the threshold
        .{ .m = aead_delegate_max - 8, .ad = 8, .want = .std_delegated, .why = "ad tops up to threshold" },
        .{ .m = aead_delegate_max - 8, .ad = 9, .want = .wide, .why = "ad tops one past" },
        .{ .m = 16, .ad = aead_delegate_max - 16, .want = .std_delegated, .why = "ad-dominant, at threshold" },
        .{ .m = 16, .ad = aead_delegate_max - 15, .want = .wide, .why = "ad-dominant, one past" },
        // the extreme: no message at all, AD does all the crossing
        .{ .m = 0, .ad = aead_delegate_max, .want = .std_delegated, .why = "ad only, at threshold" },
        .{ .m = 0, .ad = aead_delegate_max + 1, .want = .wide, .why = "ad only, one past" },
    }) |c| {
        ChaCha20Poly1305.encrypt(out[0..c.m], &tag, buf[0..c.m], buf[0..c.ad], nonce, key);
        testing.expectEqual(c.want, aead_path) catch |e| {
            std.debug.print("seal routed m={d} ad={d} ({s}) to {s}\n", .{ c.m, c.ad, c.why, @tagName(aead_path) });
            return e;
        };
        // Same case through `open`, which carries its own copy of the
        // comparison and is the side that sees attacker-chosen input.
        try ChaCha20Poly1305.decrypt(dec[0..c.m], out[0..c.m], tag, buf[0..c.ad], nonce, key);
        testing.expectEqual(c.want, aead_path) catch |e| {
            std.debug.print("open routed c={d} ad={d} ({s}) to {s}\n", .{ c.m, c.ad, c.why, @tagName(aead_path) });
            return e;
        };
        // The routing assertions above would also pass on a call that did
        // nothing at all, so pin the bytes too.
        try testing.expectEqualSlices(u8, buf[0..c.m], dec[0..c.m]);
    }

    // ── the DELIVERED numbers, in literals ──────────────────────────────────
    //
    // Everything above is symbolic, so it re-asserts whatever the constants
    // are: `aead_delegate_max` 128 -> 130 and `delegate_max_bytes` 64 -> 80
    // both exited 0 against it. These three lines are what make a retune
    // deliberate — they are the numbers `bench.zig`'s tables and this file's
    // "AFTER" comment quote, and the ones a consumer reads to know which sizes
    // get std's speed and which get this module's.
    try testing.expectEqual(@as(usize, 64), delegate_max_bytes);
    try testing.expectEqual(@as(usize, 128), aead_delegate_max);
    try testing.expectEqual(@as(usize, 8), wide); // 8 blocks = a 512-byte group

    // …and the routing those literals imply, replayed the same way as above so
    // a moved constant fails on behaviour and not only on arithmetic.
    for ([_]CipherCase{
        .{ .len = 64, .want = .std_delegated, .why = "64 B: last delegated size" },
        .{ .len = 65, .want = .wide, .why = "65 B: first wide size" },
        .{ .len = 512 + 64, .want = .std_delegated, .why = "512 B group + 64 B tail" },
        .{ .len = 512 + 65, .want = .wide, .why = "512 B group + 65 B tail" },
    }) |c| {
        ChaCha20.xor(out[0..c.len], buf[0..c.len], 1, key, nonce);
        testing.expectEqual(c.want, chacha_path) catch |e| {
            std.debug.print("xor routed {d} B ({s}) to {s}\n", .{ c.len, c.why, @tagName(chacha_path) });
            return e;
        };
        ChaCha20.stream(out[0..c.len], 1, key, nonce);
        testing.expectEqual(c.want, chacha_path) catch |e| {
            std.debug.print("stream routed {d} B ({s}) to {s}\n", .{ c.len, c.why, @tagName(chacha_path) });
            return e;
        };
    }
    for ([_]AeadCase{
        .{ .m = 128, .ad = 0, .want = .std_delegated, .why = "128 B msg: last delegated" },
        .{ .m = 129, .ad = 0, .want = .wide, .why = "129 B msg: first wide" },
        .{ .m = 16, .ad = 112, .want = .std_delegated, .why = "16+112 = 128 exactly" },
        .{ .m = 16, .ad = 113, .want = .wide, .why = "16+113 = 129, one past" },
        .{ .m = 0, .ad = 129, .want = .wide, .why = "AD alone crosses 128" },
    }) |c| {
        ChaCha20Poly1305.encrypt(out[0..c.m], &tag, buf[0..c.m], buf[0..c.ad], nonce, key);
        testing.expectEqual(c.want, aead_path) catch |e| {
            std.debug.print("seal routed m={d} ad={d} ({s}) to {s}\n", .{ c.m, c.ad, c.why, @tagName(aead_path) });
            return e;
        };
        try ChaCha20Poly1305.decrypt(dec[0..c.m], out[0..c.m], tag, buf[0..c.ad], nonce, key);
        testing.expectEqual(c.want, aead_path) catch |e| {
            std.debug.print("open routed c={d} ad={d} ({s}) to {s}\n", .{ c.m, c.ad, c.why, @tagName(aead_path) });
            return e;
        };
        try testing.expectEqualSlices(u8, buf[0..c.m], dec[0..c.m]);
    }
}

// The fused `xor` writes whole 64-byte blocks from vector registers and reaches
// the staging path only for the final partial group, so its failure modes are
// (a) a mis-transposed lane, (b) a wrong block in the discarded tail suffix, and
// (c) an off-by-one at the group/tail seam. A handful of edge lengths does not
// cover that: the tail can be any of 0..511 bytes and the tail engine switches
// between the wide group and std at `delegate_max_bytes`. Sweep EVERY length up to 1024 — two
// whole wide groups plus every possible tail — byte-exact against std.
test "exhaustive length sweep 0..1024: xor byte-exact vs std" {
    var prng = std.Random.DefaultPrng.init(0xFACE_B00C);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var msg: [1024]u8 = undefined;
    rand.bytes(&msg);
    var ours: [1024]u8 = undefined;
    var theirs: [1024]u8 = undefined;

    for (0..1025) |len| {
        for ([_]u32{ 0, 1, 7, 8, 9, 0xFFFF }) |ctr| {
            @memset(ours[0..len], 0xA5);
            @memset(theirs[0..len], 0x5A);
            ChaCha20.xor(ours[0..len], msg[0..len], ctr, key, nonce);
            StdChaCha.xor(theirs[0..len], msg[0..len], ctr, key, nonce);
            try testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
        }
        // `stream` shares the same core and tail split; hold it to the same bar.
        ChaCha20.stream(ours[0..len], 3, key, nonce);
        StdChaCha.stream(theirs[0..len], 3, key, nonce);
        try testing.expectEqualSlices(u8, theirs[0..len], ours[0..len]);
    }
}

// `out == in` is the documented in-place contract and what the AEAD's poly-key
// derivation and every network consumer use. The fused path reads a whole block
// into registers before storing it, which is what makes that safe; a version
// that stored a partial block before finishing its loads would corrupt the
// input it had not read yet. Every length up to two wide groups, in place.
test "in-place xor (out == in) matches the out-of-place result, 0..1024" {
    var prng = std.Random.DefaultPrng.init(0x1_9_1ACE);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var msg: [1024]u8 = undefined;
    rand.bytes(&msg);
    var inplace: [1024]u8 = undefined;
    var theirs: [1024]u8 = undefined;

    for (0..1025) |len| {
        @memcpy(inplace[0..len], msg[0..len]);
        ChaCha20.xor(inplace[0..len], inplace[0..len], 1, key, nonce);
        StdChaCha.xor(theirs[0..len], msg[0..len], 1, key, nonce);
        try testing.expectEqualSlices(u8, theirs[0..len], inplace[0..len]);

        // and it round-trips back to the plaintext in place
        ChaCha20.xor(inplace[0..len], inplace[0..len], 1, key, nonce);
        try testing.expectEqualSlices(u8, msg[0..len], inplace[0..len]);
    }
}

test "in-place AEAD (c == m buffer) seal/open" {
    const key = [_]u8{0x11} ** 32;
    const nonce = [_]u8{0x22} ** 12;
    var prng = std.Random.DefaultPrng.init(0xA11A5);
    var msg: [777]u8 = undefined;
    prng.random().bytes(&msg);

    inline for (.{ 0, 1, 63, 64, 65, 511, 512, 513, 777 }) |len| {
        var buf: [len]u8 = undefined;
        @memcpy(&buf, msg[0..len]);
        var tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(&buf, &tag, &buf, "ad", nonce, key);

        var std_c: [len]u8 = undefined;
        var std_tag: [16]u8 = undefined;
        StdAead.encrypt(&std_c, &std_tag, msg[0..len], "ad", nonce, key);
        try testing.expectEqualSlices(u8, &std_c, &buf);
        try testing.expectEqualSlices(u8, &std_tag, &tag);

        try ChaCha20Poly1305.decrypt(&buf, &buf, tag, "ad", nonce, key);
        try testing.expectEqualSlices(u8, msg[0..len], &buf);
    }
}

// Unaligned slices: callers hand us arbitrary `[]u8`, and the fused path uses
// unaligned vector loads/stores. Slide both `in` and `out` across every offset
// in a 64-byte window, independently, so no combination is accidentally aligned.
test "unaligned in/out offsets produce identical bytes" {
    const key = [_]u8{0x5C} ** 32;
    const nonce = [_]u8{0x3E} ** 12;
    var prng = std.Random.DefaultPrng.init(0x0DDA_1160);
    var backing_in: [64 + 600]u8 = undefined;
    var backing_out: [64 + 600]u8 = undefined;
    prng.random().bytes(&backing_in);

    const len = 600;
    var reference: [len]u8 = undefined;
    for (0..64) |in_off| {
        StdChaCha.xor(&reference, backing_in[in_off..][0..len], 1, key, nonce);
        for (0..64) |out_off| {
            @memset(&backing_out, 0);
            ChaCha20.xor(backing_out[out_off..][0..len], backing_in[in_off..][0..len], 1, key, nonce);
            try testing.expectEqualSlices(u8, &reference, backing_out[out_off..][0..len]);
        }
    }
}

test "counter increment across the wide/tail boundary (>8 blocks)" {
    // 20 blocks exercises two wide (8-block) passes + a 4-block tail and the
    // per-lane counter increment across the boundary; byte-exact vs std. A
    // non-zero start counter checks the base-counter + per-lane iota add.
    const key = [_]u8{7} ** 32;
    const nonce = [_]u8{9} ** 12;
    var ours: [20 * 64]u8 = undefined;
    var theirs: [20 * 64]u8 = undefined;
    ChaCha20.stream(&ours, 12345, key, nonce);
    StdChaCha.stream(&theirs, 12345, key, nonce);
    try testing.expectEqualSlices(u8, &theirs, &ours);
}

test "decrypt zeroes the output buffer on authentication failure (audit F3)" {
    // The doc promises `m` is zeroed on failure; make it observable. Pre-load `m`
    // with a sentinel, feed a tampered tag, and assert every byte is zero after
    // the rejection (goes RED if the secureZero is dropped back to memset-undefined).
    const key = [_]u8{3} ** 32;
    const nonce = [_]u8{5} ** 12;
    const msg = "sensitive plaintext bytes";
    var c: [msg.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&c, &tag, msg, "", nonce, key);

    var m = [_]u8{0xAA} ** msg.len; // caller sentinel
    var bad_tag = tag;
    bad_tag[0] +%= 1;
    try testing.expectError(error.AuthenticationFailed, ChaCha20Poly1305.decrypt(&m, &c, bad_tag, "", nonce, key));
    for (m) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "counter space boundary: the last non-wrapping block is accepted (audit F1)" {
    // A request that exactly consumes the remaining 32-bit counter space must
    // succeed; one more block would trip the anti-wrap assert (see `xor`). Here
    // counter = 2^32 - 1 with a single 64-byte block uses the last valid counter.
    const key = [_]u8{1} ** 32;
    const nonce = [_]u8{2} ** 12;
    var ours: [64]u8 = undefined;
    var theirs: [64]u8 = undefined;
    ChaCha20.stream(&ours, 0xFFFF_FFFF, key, nonce);
    StdChaCha.stream(&theirs, 0xFFFF_FFFF, key, nonce);
    try testing.expectEqualSlices(u8, &theirs, &ours);
}

// ── fuzz: decrypt never panics on arbitrary ciphertext/tag/AAD ────────────
//
// `ChaCha20Poly1305.decrypt` is the AEAD-open call every real caller runs on
// data straight off the wire: ciphertext, tag and AAD are all fully
// attacker-controlled (only `nonce`/`key` are locally chosen — fuzzed here
// too, since a caller could source a nonce from a peer in a misuse-resistant
// design). The overwhelming majority of random inputs fail the tag check
// (`error.AuthenticationFailed`); the harness proves that path stays
// side-channel-safe-shaped (zeroes `m`) and never panics, for every length.

test "fuzz: decrypt never panics on arbitrary ciphertext/tag/AAD/nonce/key" {
    try testing.fuzz({}, fuzzDecrypt, .{});
}

fn fuzzDecrypt(_: void, smith: *std.testing.Smith) !void {
    var c: [128]u8 = undefined;
    smith.bytes(&c);
    const len: usize = smith.valueRangeAtMost(u8, 0, c.len);

    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    smith.bytes(&tag);

    var ad: [64]u8 = undefined;
    smith.bytes(&ad);
    const ad_len: usize = smith.valueRangeAtMost(u8, 0, ad.len);

    var nonce: [ChaCha20Poly1305.nonce_length]u8 = undefined;
    smith.bytes(&nonce);
    var key: [ChaCha20Poly1305.key_length]u8 = undefined;
    smith.bytes(&key);

    var m: [128]u8 = undefined;
    ChaCha20Poly1305.decrypt(m[0..len], c[0..len], tag, ad[0..ad_len], nonce, key) catch {};
}
