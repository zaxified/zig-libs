// SPDX-License-Identifier: MIT

//! poly1305 — lane-parallel Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! `std.crypto.onetimeauth.Poly1305` evaluates the polynomial one 16-byte block
//! at a time in a 2×64-bit + 2-bit limb layout, using 64×64→128 multiplies. That
//! is a good *scalar* shape, but it is strictly serial: block `i+1`'s multiply
//! depends on block `i`'s. On this repo's AEAD hot path (ChaCha20-Poly1305 for
//! WireGuard / Noise / TLS bulk) the MAC is roughly half the total cost, and it
//! is the half that does not vectorise for free.
//!
//! ## The parallel form
//!
//! Poly1305 computes `H = Σ mᵢ · r^(n−i+1)` in GF(2^130−5). Split the blocks
//! across `L` lanes by index mod `L` and run a Horner recurrence per lane with
//! the *same* multiplier `r^L`:
//!
//!     A ← A · r^L + M      (lane-wise, M = the L blocks of one group)
//!
//! then fold the lanes at the very end with the power vector
//! `(r^L, r^(L−1), …, r^1)` and a horizontal sum. Lane `j` holding block
//! `i = j+1+tL` then contributes `r^(L(G−1−t)) · r^(L−j) = r^(n−i+1)` — the
//! required exponent. The running accumulator carried in from earlier `update`
//! calls is seeded into lane 0 of the *first* group, which gives it `r^n`.
//!
//! ## Limb layout: 5×26 bits, not 2×64
//!
//! The scalar layout cannot be vectorised on x86: there is no 64×64→128 SIMD
//! multiply. The one wide multiply SSE2/AVX2/AVX-512 do have is
//! `PMULUDQ` — 32×32→64, on the even 32-bit lanes. So the field element is held
//! as **five 26-bit limbs**: every operand then fits in 32 bits, every partial
//! product in 64, and the reduction `2^130 ≡ 5` is a shift-and-multiply-by-5.
//!
//! `PMULUDQ` is reached without an intrinsic: every multiply operand is
//! masked to its low 32 bits, `(a & 0xffffffff) * (b & 0xffffffff)` on
//! `@Vector(L, u64)` lanes — the exact pattern LLVM's x86 backend folds into
//! `vpmuludq`. In the lane loop the accumulator stays in u64 lanes from step to
//! step (no widening and narrowing per step, 2026-10-13), and the mask is applied
//! behind an empty-asm barrier (`opaque64`): IR passes otherwise prove the
//! accumulator small, delete the mask, and leave the backend — which cannot see
//! through the loop phi — to emulate a 64×64 multiply. The message blocks are
//! split into limbs straight from 64-bit words (`loadBlocks64`).
//!
//! ## Deferred-carry bounds (the part these implementations get wrong)
//!
//! Invariant entering a multiply: every limb `< 2^27.6`, `rᵢ < 2^26`,
//! `sᵢ = 5rᵢ < 2^28.33`. Each `dᵢ` is a sum of five products, so
//! `dᵢ < 5 · 2^27.6 · 2^28.33 < 2^58.3` — comfortably inside u64 with ~5 bits of
//! headroom. The carry chain masks limbs 0..4 to 26 bits, folds the top carry
//! `c < 2^32.3` back as `5c` into limb 0 (`< 2^35`), re-carries once, and leaves
//! limb 1 `< 2^26 + 2^9 < 2^27`. Adding the next message block's limb
//! (`< 2^26`) restores `< 2^27.6`. The arithmetic uses checked `*`/`+`, not
//! `*%`/`+%`, precisely so that a bounds mistake panics in Debug/ReleaseSafe
//! rather than silently forging a tag.
//!
//! ## Hybrid, because the vector form has a floor
//!
//! Lane-parallelism is not free: the `r^1..r^L` power table costs `L−1` field
//! multiplies before the first group, and the 5×26-bit layout that makes SIMD
//! possible is *worse* than 2×64 when run serially (five schoolbook rows
//! instead of one `mulx`). A pure-vector Poly1305 measured **0.47×** std at 64
//! bytes on this host — a real regression on precisely the short-packet traffic
//! (WireGuard keepalives, handshakes) that the data-plane case cares about.
//!
//! So `Generic(L)` *contains* `std.crypto.onetimeauth.Poly1305` and delegates
//! to it for the key, the leftover buffer, the tail, the final reduction and
//! the tag. It intercepts only runs of at least `wide_min_groups` whole lane
//! groups, hands those to the vector engine, and folds the accumulator back.
//! Below that threshold the code path is std's, byte for byte and cycle for
//! cycle. Measured: parity (0.94–1.01×) at ≤ 128 B, crossing over around 256 B,
//! 2.0× at 1 KiB, 2.5–2.7× at 8 KiB.
//!
//! ## Portability
//!
//! `lanes` is chosen at **comptime** from the target's features; on anything
//! without a wide integer SIMD multiply worth using it is 1, and `Poly1305` is
//! then a direct alias of `std.crypto.onetimeauth.Poly1305` — the scalar
//! 64-bit path, which beats a 26-bit-limb scalar emulation. There is no runtime
//! CPU dispatch and no x86 assumption in the vector code itself: `Generic(L)`
//! is written against `@Vector` alone and is exercised by the tests at
//! L ∈ {1,2,4,8} on every target, including ones where `lanes == 1` means the
//! shipped MAC never runs it.
//!
//! ## Constant time — in `ReleaseFast`, and measurably NOT in `ReleaseSafe`
//!
//! Add / multiply / shift / mask only. No secret-indexed load; the final
//! conditional subtraction of `2^130−5` is std's borrow-mask select, unchanged.
//! The only branches this code *writes* are on message length and buffer
//! occupancy, which are public.
//!
//! But the arithmetic above is deliberately **checked** `*`/`+`, not `*%`/`+%`
//! (see the deferred-carry section), and in `Debug`/`ReleaseSafe` the compiler
//! turns each of those into an overflow branch on a secret-derived value. So
//! the claim is mode-dependent, and the mode boundary is where it breaks —
//! measured, not reasoned, and re-measurable: `ctgrind_harness.zig` in this
//! directory is the program, `../../../scripts/ctgrind.sh chachapoly` runs it.
//!
//! ```
//!   build            -fvalgrind  key tainted   contexts   in poly1305.zig
//!   ReleaseFast          yes         yes           4            0
//!   ReleaseSafe          yes         yes         214          210
//!   Debug                yes         yes         285          281
//!   ReleaseFast          yes         NO            0            0   (control)
//!   ReleaseSafe          yes         NO            0            0   (control)
//!   Debug                yes         NO            0            0   (control)
//!   ReleaseFast          NO          yes           0            0   (trap)
//!   ReleaseSafe          NO          yes           0            0   (trap)
//!   Debug                NO          yes           0            0   (trap)
//! ```
//!
//! (valgrind/memcheck, `makeMemUndefined` over the 32-byte key, `lanes = 4`,
//! zig 0.16.0, valgrind 3.26.0, i7-7920HQ, 2026-08-11. The `ReleaseSafe`
//! innermost frames are the schoolbook rows of `mulRed`, the carry chain, and
//! `buildPowers`' power table — i.e. exactly the checked operators.)
//!
//! Read the control rows before reading the `ReleaseFast` zero. Untainted,
//! every mode reports 0, so the 4 `ReleaseFast` contexts are taint-caused —
//! they are branches on the *tag*, inside the harness's own formatter, which is
//! what proves the taint travelled key → tag through the whole MAC and left no
//! branch behind on the way. And **without `-fvalgrind` every row reads 0**:
//! `std.valgrind.doClientRequest` returns early unless `builtin.valgrind_support`,
//! which the release modes disable, so a clean run built without the switch is
//! a no-op, not a result.
//!
//! The checked operators STAY. A deferred-carry bounds mistake that panics is
//! strictly better than one that silently forges a tag, and the branches in
//! question are never *taken* on correct input — what `ReleaseSafe` loses is
//! the machine-checkable absence of the branch, not a demonstrated leak. The
//! contract, therefore: **ship `ReleaseFast` if constant time matters.**

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;

/// Number of blocks authenticated per multiply step. Comptime-selected; 1 means
/// "no SIMD win available here, use the std scalar MAC".
///
/// * AVX-512F: `@Vector(8, u64)` is one zmm → 8 `vpmuludq` lanes.
/// * AVX2:     8 lanes too — two ymm per limb, i.e. two independent 4-lane
///             Horner chains the core can overlap. A 4-lane step is one
///             dependency chain per 64 bytes and the loop waited on it:
///             measured 2026-10-13 (i7-7920HQ), L = 8 against L = 4 is
///             0.63 vs 0.77 cycles/B at 16 KiB, 0.72 vs 0.83 at 1420 B. Runs
///             too short for 8 lanes (192–383 B) take the 4-lane half engine
///             (see `Generic`), so the vector entry point stays at 192 B.
/// * else:     scalar. SSE2 would give 2 lanes, and NEON's `umull` likewise,
///             but 2×26-bit lanes does not beat a 64×64→128 scalar multiply, so
///             claiming it would be a pessimisation dressed as portability.
pub const lanes: usize = if (builtin.cpu.has(.x86, .avx512f) or builtin.cpu.has(.x86, .avx2))
    8
else
    1;

/// True when `Poly1305` below is the vector implementation rather than std's.
pub const simd_active = lanes > 1;

// ── engine witness: the ONLY thing that can see a wrong `wide_min_groups` ────
//
// Every test in this file compares bytes, and both engines produce the same
// bytes — the wide path exists to be *faster*, not different. So moving
// `wide_min_groups` (or reversing its comparison) leaves every RFC 8439 vector,
// every length-sweep differential against std and every fuzz case GREEN while
// switching the lane-parallel MAC off entirely: measured, `wide_min_groups = 3
// → 4096` cost the 8 KiB MAC 4048 → 1698 MB/s (2.47× → 1.06× vs std) and the
// AEAD 1504 → 941, with `zig build test-chachapoly` still exit 0.
//
// `root.zig` already carries exactly this device for its two delegation
// thresholds (`chacha_path` / `aead_path`); this is the same device for the
// third threshold, which had none. Same rules as there: `is_test` is comptime,
// so outside a test build `Witness` is `void`, `note` is a store to a
// zero-sized value, nothing reaches the object file, and the module's
// `.reentrant` claim is untouched because the mutable state only exists in a
// single-threaded test binary. It is not runtime dispatch and non-test code
// must never read it.

/// Which engine the last `update` call used for its bulk: std's serial core,
/// the `L`-lane engine, or (at `L ≥ 8`) the `L/2`-lane engine for runs too
/// short for `L` lanes.
pub const Path = enum { serial_std, wide, wide_half };

const Witness = if (builtin.is_test) Path else void;
const witness_init: Witness = if (builtin.is_test) .serial_std else {};

/// Engine taken by the last `Generic(L).update` call, at any `L`.
pub var mac_path: Witness = witness_init;

inline fn note(p: Path) void {
    if (builtin.is_test) mac_path = p;
}

/// The MAC this module's AEAD uses. API-identical to
/// `std.crypto.onetimeauth.Poly1305` either way.
pub const Poly1305 = if (simd_active) Generic(lanes) else std.crypto.onetimeauth.Poly1305;

const limb_mask: u32 = 0x3ff_ffff; // 2^26 − 1

/// Widen a `[5]@Vector(W, u32)` limb set to u64 lanes. The `@intCast` is a
/// zero-extend, which is what makes the `mul` foldable into `vpmuludq`.
fn widen(comptime W: usize, v: [5]@Vector(W, u32)) [5]@Vector(W, u64) {
    var out: [5]@Vector(W, u64) = undefined;
    inline for (0..5) |i| out[i] = @intCast(v[i]);
    return out;
}

/// `h · r mod 2^130−5`, lane-wise, in 5×26-bit limbs held in u64 lanes (the
/// value in the low 32 bits). `s[i]` must be `5·r[i]`. Returns limbs
/// satisfying the deferred-carry invariant documented above.
///
/// Every multiply operand is masked to its low 32 bits: `(a & 0xffffffff) *
/// (b & 0xffffffff)` is the pattern LLVM's x86 backend folds into
/// `vpmuludq` unconditionally. Without the masks it had to PROVE the upper
/// halves zero, which known-bits analysis does not do across the loop's phi
/// (2026-10-13: the u64 accumulator then multiplied as emulated 64×64, 25 %
/// slower). The masks cost nothing — `vpmuludq` ignores the upper halves.
inline fn mulRed64(
    comptime W: usize,
    h: [5]@Vector(W, u64),
    r: [5]@Vector(W, u64),
    s: [5]@Vector(W, u64),
) [5]@Vector(W, u64) {
    const V64 = @Vector(W, u64);
    const mask: V64 = @splat(limb_mask);
    const lo32: V64 = @splat(0xffff_ffff);
    const sh26: @Vector(W, u6) = @splat(26);

    var a: [5]V64 = undefined;
    var b: [5]V64 = undefined;
    var c5: [5]V64 = undefined;
    inline for (0..5) |i| {
        a[i] = opaque64(W, h[i]) & lo32;
        b[i] = r[i] & lo32;
        c5[i] = s[i] & lo32;
    }

    // Schoolbook 5×5 with the 2^130 ≡ 5 wrap already folded in via s = 5r.
    var d: [5]V64 = .{
        a[0] * b[0] + a[1] * c5[4] + a[2] * c5[3] + a[3] * c5[2] + a[4] * c5[1],
        a[0] * b[1] + a[1] * b[0] + a[2] * c5[4] + a[3] * c5[3] + a[4] * c5[2],
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * c5[4] + a[4] * c5[3],
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * c5[4],
        a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
    };

    // Deferred carry: propagate once through the limbs, wrap the top back as 5c.
    var carry: V64 = d[0] >> sh26;
    d[0] &= mask;
    inline for (1..5) |i| {
        d[i] += carry;
        carry = d[i] >> sh26;
        d[i] &= mask;
    }
    const five: V64 = @splat(5);
    d[0] += carry * five;
    carry = d[0] >> sh26;
    d[0] &= mask;
    d[1] += carry; // < 2^26 + 2^9; the invariant allows < 2^27.6
    return d;
}

/// An empty asm statement the value passes through, so LLVM knows nothing
/// about its bits. In the loop the accumulator is provably < 2^28, so IR
/// passes delete `h & 0xffffffff` as redundant — and the backend, which sees
/// the accumulator only through the loop phi, can then no longer prove the
/// upper halves zero and emulates every product as 64×64 (three `vpmuludq`,
/// two shifts, two adds; measured 1.10 → 1.24× OpenSSL at 16 KiB,
/// 2026-10-13). Behind the barrier the mask is not redundant, so it stays and
/// `vpmuludq` is selected. x86 LLVM only (elsewhere a no-op), and per
/// register: a 512-bit vector on AVX2 is passed as two 256-bit halves, since
/// `"x"` cannot hold it whole.
inline fn opaque64(comptime W: usize, v: @Vector(W, u64)) @Vector(W, u64) {
    const bits = 64 * W;
    const reg_bits: usize = if (has_avx512f) 512 else if (has_avx) 256 else 128;
    // W = 1 (`mul1`, outside any loop) is a scalar to LLVM: no "x" register.
    if (comptime !asm_barrier_ok or W < 2) return v;
    if (comptime bits <= reg_bits) return asm (""
        : [out] "=x" (-> @Vector(W, u64)),
        : [in] "0" (v),
    );
    const H = W / 2;
    const idx = comptime blk: {
        var lo: [H]i32 = undefined;
        var hi: [H]i32 = undefined;
        var join: [W]i32 = undefined;
        for (0..H) |k| {
            lo[k] = k;
            hi[k] = H + k;
            join[k] = k; // from `lo`
            join[H + k] = ~@as(i32, k); // from `hi`
        }
        break :blk .{ lo, hi, join };
    };
    const lo = opaque64(H, @shuffle(u64, v, undefined, @as(@Vector(H, i32), idx[0])));
    const hi = opaque64(H, @shuffle(u64, v, undefined, @as(@Vector(H, i32), idx[1])));
    return @shuffle(u64, lo, hi, @as(@Vector(W, i32), idx[2]));
}

const asm_barrier_ok = builtin.zig_backend == .stage2_llvm and builtin.cpu.arch.isX86();
const has_avx = builtin.cpu.has(.x86, .avx);
const has_avx512f = builtin.cpu.has(.x86, .avx512f);

/// `mulRed64` on u32 limbs (the power table and the width-1 multiply): the
/// same arithmetic, so the table cannot diverge from the loop's.
fn mulRed(
    comptime W: usize,
    h: [5]@Vector(W, u32),
    r: [5]@Vector(W, u32),
    s: [5]@Vector(W, u32),
) [5]@Vector(W, u32) {
    const d = mulRed64(W, widen(W, h), widen(W, r), widen(W, s));
    var out: [5]@Vector(W, u32) = undefined;
    inline for (0..5) |i| out[i] = @truncate(d[i]);
    return out;
}

/// Split `W` consecutive 16-byte blocks into 5×26-bit limbs, one block per lane,
/// with the implicit 2^128 bit set. The wide path only ever sees *whole*
/// blocks — the zero-padded final block is the serial engine's job — so the
/// high bit is unconditional here.
fn loadBlocks(comptime W: usize, m: *const [16 * W]u8) [5]@Vector(W, u32) {
    const V = @Vector(W, u32);
    const t = if (W == 8 and native_endian == .little) columns8(m) else blk: {
        var cols: [4][W]u32 = undefined;
        inline for (0..W) |j| {
            inline for (0..4) |k| {
                cols[k][j] = mem.readInt(u32, m[16 * j + 4 * k ..][0..4], .little);
            }
        }
        break :blk [4]V{ cols[0], cols[1], cols[2], cols[3] };
    };
    const t0: V = t[0];
    const t1: V = t[1];
    const t2: V = t[2];
    const t3: V = t[3];
    const mask: V = @splat(limb_mask);
    const hi: V = @splat(1 << 24);
    const s6: @Vector(W, u5) = @splat(6);
    const s8: @Vector(W, u5) = @splat(8);
    const s12: @Vector(W, u5) = @splat(12);
    const s14: @Vector(W, u5) = @splat(14);
    const s18: @Vector(W, u5) = @splat(18);
    const s20: @Vector(W, u5) = @splat(20);
    const s26: @Vector(W, u5) = @splat(26);
    return .{
        t0 & mask,
        ((t0 >> s26) | (t1 << s6)) & mask,
        ((t1 >> s20) | (t2 << s12)) & mask,
        ((t2 >> s14) | (t3 << s18)) & mask,
        (t3 >> s8) | hi,
    };
}

/// Word `k` of each of 8 consecutive 16-byte blocks, block `j` in lane `j`,
/// from four 32-byte loads and register shuffles (`vpunpck{l,h}dq`,
/// `vpunpck{l,h}qdq`, one `vpermd` per column). The per-word gather it
/// replaces lowered to 32 `vpinsrd` per 128 bytes (2026-10-13).
inline fn columns8(m: *const [128]u8) [4]@Vector(8, u32) {
    const V = @Vector(8, u32);
    // y[p] = block 2p's words 0..3 | block 2p+1's words 0..3.
    // Through `@Vector(32, u8)`: zig 0.17 lowers a byte-array -> u32-vector
    // `@bitCast` to a byte-by-byte integer assembly (~140 instructions per
    // 32 bytes); the u8-vector load plus a vector -> vector `@bitCast` is one
    // `vmovdqu`, with the same little-endian-logical meaning on every target.
    const B = @Vector(32, u8);
    const y: [4]V = .{
        @bitCast(@as(B, m[0..32].*)),
        @bitCast(@as(B, m[32..64].*)),
        @bitCast(@as(B, m[64..96].*)),
        @bitCast(@as(B, m[96..128].*)),
    };
    const lo32 = @Vector(8, i32){ 0, ~@as(i32, 0), 1, ~@as(i32, 1), 4, ~@as(i32, 4), 5, ~@as(i32, 5) };
    const hi32 = @Vector(8, i32){ 2, ~@as(i32, 2), 3, ~@as(i32, 3), 6, ~@as(i32, 6), 7, ~@as(i32, 7) };
    const lo64 = @Vector(8, i32){ 0, 1, ~@as(i32, 0), ~@as(i32, 1), 4, 5, ~@as(i32, 4), ~@as(i32, 5) };
    const hi64 = @Vector(8, i32){ 2, 3, ~@as(i32, 2), ~@as(i32, 3), 6, 7, ~@as(i32, 6), ~@as(i32, 7) };
    // a = [b0w0 b2w0 b0w1 b2w1 | b1w0 b3w0 b1w1 b3w1], b likewise for blocks 4..7.
    const a = @shuffle(u32, y[0], y[1], lo32);
    const b = @shuffle(u32, y[2], y[3], lo32);
    const c = @shuffle(u32, y[0], y[1], hi32);
    const d = @shuffle(u32, y[2], y[3], hi32);
    // Lane order after the 64-bit unpack: blocks 0 2 4 6 1 3 5 7.
    const order = @Vector(8, i32){ 0, 4, 1, 5, 2, 6, 3, 7 };
    return .{
        @shuffle(u32, @shuffle(u32, a, b, lo64), undefined, order),
        @shuffle(u32, @shuffle(u32, a, b, hi64), undefined, order),
        @shuffle(u32, @shuffle(u32, c, d, lo64), undefined, order),
        @shuffle(u32, @shuffle(u32, c, d, hi64), undefined, order),
    };
}

const native_endian = builtin.cpu.arch.endian();

/// Whether `loadBlocks64` takes the 64-bit-word shuffle (W = 4 or 8 on a
/// little-endian target) — which permutes the blocks across lanes, see
/// `laneBlock` — or widens `loadBlocks`' u32 limbs in block order.
fn qwordLoad(comptime W: usize) bool {
    return (W == 4 or W == 8) and native_endian == .little;
}

/// The block (within a group of `W`) that `loadBlocks64` puts in lane `j`.
/// `vpunpck{l,h}qdq` interleave within 128-bit halves, so each 4-block run
/// lands as blocks 0 2 1 3. The fold vectors are built from this map, so lane
/// `j` is multiplied by `r^(W − laneBlock(W, j))` — the power its block needs.
/// Lane 0 is always block 0, where the carried-in accumulator is seeded.
fn laneBlock(comptime W: usize, comptime j: usize) usize {
    if (!qwordLoad(W)) return j;
    const quad = [4]usize{ 0, 2, 1, 3 };
    return (j / 4) * 4 + quad[j % 4];
}

/// Split `W` consecutive 16-byte blocks into 5×26-bit limbs in u64 lanes (one
/// block per lane, in `laneBlock` order), with the implicit 2^128 bit set. At
/// W = 4 / 8 straight from 64-bit words: the low and high quadwords of each
/// block come out of `vpunpck{l,h}qdq` already in 64-bit lanes, and the limbs
/// are shifts and masks of them — no u32 → u64 widening per step.
inline fn loadBlocks64(comptime W: usize, m: *const [16 * W]u8) [5]@Vector(W, u64) {
    const V64 = @Vector(W, u64);
    if (comptime !qwordLoad(W)) return widen(W, loadBlocks(W, m));
    // Via `@Vector(16 * W, u8)`, not `@bitCast(m.*)`: zig 0.17 (LLVM 22)
    // lowers a byte-array -> u64-vector `@bitCast` to a byte-at-a-time shift
    // loop through a wide integer (2026-10-18: `update` 620K -> 8.98M Ir at
    // 16 KiB). The u8-vector load is plain `vmovdqu`s and the vector -> vector
    // `@bitCast` is free; both are little-endian-logical on every target, so
    // the lanes are the same quadwords as before.
    const q: @Vector(2 * W, u64) = @bitCast(@as(@Vector(16 * W, u8), m.*));
    // Quadword 2b is block b's low half, 2b+1 its high half; per pair of
    // 32-byte loads the unpack yields blocks 0 2 1 3.
    const lo_idx = comptime blk: {
        var a: [W]i32 = undefined;
        for (0..W) |j| a[j] = @intCast(2 * laneBlock(W, j));
        break :blk a;
    };
    const hi_idx = comptime blk: {
        var a: [W]i32 = undefined;
        for (0..W) |j| a[j] = @intCast(2 * laneBlock(W, j) + 1);
        break :blk a;
    };
    const lo = @shuffle(u64, q, undefined, @as(@Vector(W, i32), lo_idx));
    const hi = @shuffle(u64, q, undefined, @as(@Vector(W, i32), hi_idx));
    const mask: V64 = @splat(limb_mask);
    const s12: @Vector(W, u6) = @splat(12);
    const s14: @Vector(W, u6) = @splat(14);
    const s24: @Vector(W, u6) = @splat(24);
    const s26: @Vector(W, u6) = @splat(26);
    const s40: @Vector(W, u6) = @splat(40);
    const s52: @Vector(W, u6) = @splat(52);
    const top: V64 = @splat(1);
    return .{
        lo & mask,
        (lo >> s26) & mask,
        ((lo >> s52) | (hi << s12)) & mask,
        (hi >> s14) & mask,
        (hi >> s40) | (top << s24),
    };
}

/// Carry a 5-limb value whose limbs may be up to ~2^32 back into the
/// `< 2^26` (limb 1: `< 2^27`) invariant. Used after the lane fold and on the
/// scalar accumulator.
fn carryLimbs(x: [5]u64) [5]u32 {
    var d = x;
    var carry: u64 = d[0] >> 26;
    d[0] &= limb_mask;
    inline for (1..5) |i| {
        d[i] += carry;
        carry = d[i] >> 26;
        d[i] &= limb_mask;
    }
    d[0] += carry * 5;
    carry = d[0] >> 26;
    d[0] &= limb_mask;
    d[1] += carry;

    var out: [5]u32 = undefined;
    inline for (0..5) |i| out[i] = @truncate(d[i]);
    return out;
}

/// Lane-parallel Poly1305 over `L` blocks per step.
///
/// **Hybrid, on purpose.** The lane-parallel engine only wins once there are
/// enough blocks to amortise the `r^1..r^L` power table, and the 5×26-bit limb
/// layout that makes SIMD possible is *worse* than a 2×64-bit layout when run
/// serially (five schoolbook rows instead of one 64×64→128 multiply). Measured
/// on this repo's bench, a pure-vector Poly1305 authenticating 64 bytes ran at
/// **0.47×** the std scalar MAC — a real regression on exactly the short-packet
/// traffic (WireGuard keepalives, handshakes) the data-plane case cares about.
///
/// So the serial engine here *is* `std.crypto.onetimeauth.Poly1305`: it owns
/// the clamped key, the leftover buffer, the final reduction and the tag. This
/// type intercepts only long runs of whole blocks, hands them to the vector
/// engine, and folds the result back. Short inputs are then bit-for-bit std at
/// std's speed, and the SIMD win applies where it is actually a win.
///
/// `L = 1` degenerates to plain std (the `L > 1` guard removes the wide path
/// entirely); it is still instantiated by the tests as a control.
pub fn Generic(comptime L: usize) type {
    return struct {
        const Self = @This();
        const V = @Vector(L, u32);

        pub const block_length: usize = 16;
        pub const mac_length = 16;
        pub const key_length = 32;

        /// Whole lane-groups required before the wide path is taken. Below this
        /// the power-table build (L−1 field multiplies plus normalisation)
        /// costs more than the lanes save. Tuned by measurement — see the
        /// module bench's `poly1305 64B` / `aead 1420B packet` lines.
        const wide_min_groups = 3;
        const wide_min_bytes = block_length * L * wide_min_groups;

        /// At `L ≥ 8` a run of `3·H .. 3·L` blocks (`H = L/2`) goes through an
        /// `H`-lane engine over the same power table instead of std: measured
        /// 2026-10-13, L = 8 alone sent 192–383 B to std at 1.9 cycles/B where
        /// 4 lanes ran 1.0–1.25. `H = 0` means no half engine.
        const H: usize = if (L >= 8) L / 2 else 0;
        const HalfV = @Vector(@max(H, 1), u32);
        const half_min_bytes = block_length * H * wide_min_groups;
        /// The shortest bulk any vector engine takes.
        const entry_bytes = if (H > 0) half_min_bytes else wide_min_bytes;

        /// The serial engine and the single source of truth for the
        /// accumulator, the leftover buffer, the key and the tag.
        ///
        /// Three of its fields are read across the seam, all public, all with a
        /// meaning forced by the algorithm rather than by std's choices:
        ///
        ///   * `h` — the partially-reduced accumulator
        ///     `h[0] + h[1]·2^64 + h[2]·2^128`, `h[2]` small. Read on entry to
        ///     the wide path and written back on exit.
        ///   * `r` — the *clamped* key half, `r[0] + r[1]·2^64`. Re-split into
        ///     26-bit limbs when the power table is built. Taking it from here
        ///     rather than re-clamping means there is exactly one clamp in the
        ///     program.
        ///   * `leftover` — how full the partial-block buffer is, so the wide
        ///     path can tell whether it is on a block boundary.
        ///
        /// Any drift in those meanings fails the length-sweep differential in
        /// this file immediately — it is not a silent coupling.
        inner: std.crypto.onetimeauth.Poly1305,

        /// r^L and 5·r^L, for the lane-wise Horner step.
        rl: [5]u32 = undefined,
        sl: [5]u32 = undefined,
        /// Lane j holds r^(L−j) / 5·r^(L−j), for the final lane fold.
        rp: [5]V = undefined,
        sp: [5]V = undefined,
        /// The half engine's r^H, 5·r^H and its fold vectors (lane j holds
        /// r^(H−j)); unused when `H = 0`.
        rh: [5]u32 = undefined,
        sh: [5]u32 = undefined,
        rph: [5]HalfV = undefined,
        sph: [5]HalfV = undefined,
        /// Built lazily on first use of the wide path.
        powers_ready: bool = false,

        /// Nothing here but std's own init: a message that never reaches the
        /// wide path must cost exactly what std costs, setup included.
        pub fn init(key: *const [key_length]u8) Self {
            return .{ .inner = std.crypto.onetimeauth.Poly1305.init(key) };
        }

        /// Fully normalise to `< 2^26` per limb, so that `5·limb` stays under
        /// the `s < 2^28.33` bound `mulRed` assumes. Two carry passes suffice:
        /// the first leaves limb 1 `< 2^26 + 2^9`, the second drains it.
        fn normalize(x: [5]u32) [5]u32 {
            var w: [5]u64 = undefined;
            inline for (0..5) |i| w[i] = x[i];
            const a = carryLimbs(w);
            inline for (0..5) |i| w[i] = a[i];
            return carryLimbs(w);
        }

        /// One field multiply at width 1 — the same `mulRed` the wide path
        /// uses, so the power table cannot diverge from the loop's arithmetic.
        fn mul1(a: [5]u32, b: [5]u32, b5: [5]u32) [5]u32 {
            var av: [5]@Vector(1, u32) = undefined;
            var bv: [5]@Vector(1, u32) = undefined;
            var b5v: [5]@Vector(1, u32) = undefined;
            inline for (0..5) |i| {
                av[i] = @splat(a[i]);
                bv[i] = @splat(b[i]);
                b5v[i] = @splat(b5[i]);
            }
            const p = mulRed(1, av, bv, b5v);
            var out: [5]u32 = undefined;
            inline for (0..5) |i| out[i] = p[i][0];
            return out;
        }

        fn buildPowers(st: *Self) void {
            // Re-split std's already-clamped r (RFC 8439 §2.5) into 26-bit
            // limbs. `inner.r` is `r[0] + r[1]·2^64`, so r < 2^124 and every
            // limb below is < 2^26 without a further carry.
            const rlo = st.inner.r[0];
            const rhi = st.inner.r[1];
            const r: [5]u32 = .{
                @truncate(rlo & limb_mask),
                @truncate((rlo >> 26) & limb_mask),
                @truncate(((rlo >> 52) | (rhi << 12)) & limb_mask),
                @truncate((rhi >> 14) & limb_mask),
                @truncate((rhi >> 40) & limb_mask),
            };
            var s: [5]u32 = undefined;
            inline for (0..5) |i| s[i] = r[i] * 5;

            var pw: [L][5]u32 = undefined;
            pw[0] = r;
            inline for (1..L) |k| pw[k] = normalize(mul1(pw[k - 1], r, s));

            st.rl = pw[L - 1];
            inline for (0..5) |i| st.sl[i] = st.rl[i] * 5;

            // Lane j holds block laneBlock(L, j) of each group, which needs
            // r^(L − that block): lane of block 0 → r^L, of block L−1 → r^1.
            var rp: [5][L]u32 = undefined;
            var sp: [5][L]u32 = undefined;
            inline for (0..L) |j| {
                const p = pw[L - 1 - laneBlock(L, j)];
                inline for (0..5) |i| {
                    rp[i][j] = p[i];
                    sp[i][j] = p[i] * 5;
                }
            }
            inline for (0..5) |i| {
                st.rp[i] = rp[i];
                st.sp[i] = sp[i];
            }

            if (H > 0) {
                st.rh = pw[H - 1];
                inline for (0..5) |i| st.sh[i] = st.rh[i] * 5;
                var rph: [5][H]u32 = undefined;
                var sph: [5][H]u32 = undefined;
                inline for (0..H) |j| {
                    const p = pw[H - 1 - laneBlock(H, j)];
                    inline for (0..5) |i| {
                        rph[i][j] = p[i];
                        sph[i][j] = p[i] * 5;
                    }
                }
                inline for (0..5) |i| {
                    st.rph[i] = rph[i];
                    st.sph[i] = sph[i];
                }
            }
            st.powers_ready = true;
        }

        /// std's `[3]u64` accumulator → 5×26-bit limbs. `h[2] < 8` holds for
        /// std's partial reduction, so limb 4 stays under 2^27 and the
        /// subsequent carry brings everything back into range.
        fn importAcc(h: [3]u64) [5]u32 {
            const w: [5]u64 = .{
                h[0] & limb_mask,
                (h[0] >> 26) & limb_mask,
                ((h[0] >> 52) | (h[1] << 12)) & limb_mask,
                (h[1] >> 14) & limb_mask,
                (h[1] >> 40) | (h[2] << 24),
            };
            return carryLimbs(w);
        }

        /// 5×26-bit limbs → std's `[3]u64`. The input is fully normalised first,
        /// so the result satisfies `h < 2^130` and `h[2] <= 3` — well inside
        /// what std's block loop expects to be handed.
        fn exportAcc(limbs: [5]u32) [3]u64 {
            const f = normalize(limbs);
            return .{
                @as(u64, f[0]) | (@as(u64, f[1]) << 26) | (@as(u64, f[2]) << 52),
                (@as(u64, f[2]) >> 12) | (@as(u64, f[3]) << 14) | (@as(u64, f[4]) << 40),
                @as(u64, f[4]) >> 24,
            };
        }

        /// Absorb `m` (a whole number of `L`-block groups) through the vector
        /// engine. The power table must already be built (`update` does it).
        fn wide(st: *Self, m: []const u8) void {
            std.debug.assert(m.len % (block_length * L) == 0 and m.len > 0);

            // Group 0: A = M₀, with the carried-in accumulator seeded into lane
            // 0 so that it ends up multiplied by r^n like every other term.
            const V64 = @Vector(L, u64);
            const seed_limbs = importAcc(st.inner.h);
            var acc = loadBlocks64(L, m[0..][0 .. block_length * L]);
            inline for (0..5) |k| {
                var seed: [L]u64 = @splat(0);
                seed[0] = seed_limbs[k]; // lane 0 is block 0 (`laneBlock`)
                acc[k] += @as(V64, seed);
            }

            var rlv: [5]V64 = undefined;
            var slv: [5]V64 = undefined;
            inline for (0..5) |k| {
                rlv[k] = @splat(st.rl[k]);
                slv[k] = @splat(st.sl[k]);
            }

            // The accumulator stays in u64 lanes across the loop: no
            // u32 → u64 widening and no narrowing back per step.
            var i: usize = block_length * L;
            while (i < m.len) : (i += block_length * L) {
                acc = mulRed64(L, acc, rlv, slv);
                const lm = loadBlocks64(L, m[i..][0 .. block_length * L]);
                inline for (0..5) |k| acc[k] += lm[k];
            }

            // Fold the lanes: multiply lane j by r^(L−j), then sum lanes.
            const folded = mulRed64(L, acc, widen(L, st.rp), widen(L, st.sp));
            var sum: [5]u64 = .{ 0, 0, 0, 0, 0 };
            inline for (0..5) |k| {
                inline for (0..L) |j| sum[k] += folded[k][j];
            }
            st.inner.h = exportAcc(carryLimbs(sum));
        }

        /// `wide` over `H` lanes with the half tables, for runs too short for
        /// `L` (`H > 0` only). A deliberate copy of `wide`, not a shared
        /// generic: one function over both widths (tables picked by a comptime
        /// flag, or passed in) lost LLVM's `vpmuludq` selection in the L-lane
        /// loop — it emulated 64×64 multiplies, 16 KiB at L = 8 went 0.64 →
        /// 1.17 cycles/B (2026-10-13). The byte-exact tests against std at the
        /// half engine's lengths pin the two copies to the same arithmetic.
        fn wideHalf(st: *Self, m: []const u8) void {
            std.debug.assert(H > 0 and m.len % (block_length * H) == 0 and m.len > 0);

            const V64 = @Vector(H, u64);
            const seed_limbs = importAcc(st.inner.h);
            var acc = loadBlocks64(H, m[0..][0 .. block_length * H]);
            inline for (0..5) |k| {
                var seed: [H]u64 = @splat(0);
                seed[0] = seed_limbs[k]; // lane 0 is block 0 (`laneBlock`)
                acc[k] += @as(V64, seed);
            }

            var rlv: [5]V64 = undefined;
            var slv: [5]V64 = undefined;
            inline for (0..5) |k| {
                rlv[k] = @splat(st.rh[k]);
                slv[k] = @splat(st.sh[k]);
            }

            // The accumulator stays in u64 lanes across the loop: no
            // u32 → u64 widening and no narrowing back per step.
            var i: usize = block_length * H;
            while (i < m.len) : (i += block_length * H) {
                acc = mulRed64(H, acc, rlv, slv);
                const lm = loadBlocks64(H, m[i..][0 .. block_length * H]);
                inline for (0..5) |k| acc[k] += lm[k];
            }

            const folded = mulRed64(H, acc, widen(H, st.rph), widen(H, st.sph));
            var sum: [5]u64 = .{ 0, 0, 0, 0, 0 };
            inline for (0..5) |k| {
                inline for (0..H) |j| sum[k] += folded[k][j];
            }
            st.inner.h = exportAcc(carryLimbs(sum));
        }

        pub fn update(st: *Self, m: []const u8) void {
            // Fast path: too short for the wide engine even after the current
            // partial block is filled, so this is pure std. One predictable
            // branch — the short-packet case must not pay for the wide path's
            // bookkeeping.
            if (L == 1 or m.len + block_length < entry_bytes) {
                note(.serial_std);
                st.inner.update(m);
                return;
            }

            var mb = m;

            // 1. Top up any partial block through the serial engine, so the
            //    wide path always starts on a block boundary.
            if (st.inner.leftover > 0) {
                const want = @min(block_length - st.inner.leftover, mb.len);
                st.inner.update(mb[0..want]);
                mb = mb[want..];
            }

            // 2. Long run of whole blocks → vector engine, whole groups only:
            //    L lanes from 3·L blocks, H lanes from 3·H. The power table is
            //    built here, the one call site, so it inlines (as two call
            //    sites it did not, and cost ~500 cycles a call, 2026-10-13).
            const aligned = st.inner.leftover == 0;
            const use_wide = L > 1 and aligned and mb.len >= wide_min_bytes;
            const use_half = H > 0 and aligned and !use_wide and mb.len >= half_min_bytes;
            if ((use_wide or use_half) and !st.powers_ready) st.buildPowers();
            if (use_wide) {
                note(.wide);
                const groups = mb.len / (block_length * L);
                st.wide(mb[0 .. groups * block_length * L]);
                mb = mb[groups * block_length * L ..];
            } else if (use_half) {
                // Too short for L lanes (< 3·L blocks), long enough for H.
                note(.wide_half);
                const groups = mb.len / (block_length * H);
                st.wideHalf(mb[0 .. groups * block_length * H]);
                mb = mb[groups * block_length * H ..];
            } else {
                note(.serial_std);
            }

            // 3. The remainder (< L blocks, plus any trailing partial) is
            //    serial: std's 2×64-bit core beats the 26-bit layout here.
            if (mb.len > 0) st.inner.update(mb);
        }

        /// Zero-pad to align the next input to the first byte of a block.
        pub fn pad(st: *Self) void {
            st.inner.pad();
        }

        pub fn final(st: *Self, out: *[mac_length]u8) void {
            st.inner.final(out); // wipes `inner`, including the key material

            // The power table is r^1..r^L — secret-derived, and outside
            // `inner`, so std's wipe does not reach it. Wiped only if it was
            // ever built: a short message never touches it, and an
            // unconditional wipe of ~180 bytes is a measurable tax on exactly
            // the short-packet path this hybrid exists to protect.
            if (st.powers_ready) {
                std.crypto.secureZero(u32, &st.rl);
                std.crypto.secureZero(u32, &st.sl);
                std.crypto.secureZero(u8, mem.asBytes(&st.rp));
                std.crypto.secureZero(u8, mem.asBytes(&st.sp));
                if (H > 0) {
                    std.crypto.secureZero(u32, &st.rh);
                    std.crypto.secureZero(u32, &st.sh);
                    std.crypto.secureZero(u8, mem.asBytes(&st.rph));
                    std.crypto.secureZero(u8, mem.asBytes(&st.sph));
                }
                st.powers_ready = false;
            }
        }

        pub fn create(out: *[mac_length]u8, msg: []const u8, key: *const [key_length]u8) void {
            var st = Self.init(key);
            st.update(msg);
            st.final(out);
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const StdPoly = std.crypto.onetimeauth.Poly1305;

/// Every width, on every target: L = 1 is the degenerate scalar case, 2 and 4
/// straddle the SSE2/AVX2 shapes, 8 is the AVX-512 shape. Instantiating all of
/// them here means the vector code is differentially anchored even on a build
/// where `lanes == 1` selects the std MAC.
const widths = [_]usize{ 1, 2, 4, 8 };

// RFC 8439 §2.5.2 — the worked Poly1305 example.
test "RFC 8439 §2.5.2 worked example, every lane width" {
    const key = [_]u8{
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    const msg = "Cryptographic Forum Research Group";
    const expected = [_]u8{
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };
    inline for (widths) |L| {
        var tag: [16]u8 = undefined;
        Generic(L).create(&tag, msg, &key);
        try testing.expectEqualSlices(u8, &expected, &tag);
    }
}

// RFC 8439 §A.3 — the Poly1305 test-vector table. These are exactly the edge
// cases a parallel implementation breaks on: an all-zero r (every product
// vanishes), an all-zero s, r = 2^130−6 with a message that forces the final
// conditional subtraction, and the two "imperfect carry propagation" vectors
// #10/#11 that were written to catch a wrong carry chain.
const A3Vector = struct { key: [32]u8, msg: []const u8, tag: [16]u8 };

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "RFC 8439 §A.3 Poly1305 vectors, every lane width" {
    // #1: r = 0, s = 0 over 64 zero bytes → zero tag.
    const v1_key = @as([32]u8, @splat(0));
    const v1_msg = @as([64]u8, @splat(0));
    const v1_tag = @as([16]u8, @splat(0));

    // #2: r = 0, s ≠ 0 → the tag is s itself, whatever the message.
    const v2_key = hex("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e");
    const v2_msg = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
    const v2_tag = hex("36e5f6b5c5e06070f0efca96227a863e");

    // #3: the mirror of #2 — r ≠ 0, s = 0.
    const v3_key = hex("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000");
    const v3_msg = v2_msg;
    const v3_tag = hex("f3477e7cd95417af89a6b8794c310cf0");

    // #4: 127 bytes — an odd length that lands mid-lane for every L.
    const v4_key = hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
    const v4_msg = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";
    const v4_tag = hex("4541669a7eaaee61e708dc7cbcc5eb62");

    // #5: r = 2 and a 2^128−1 message — forces the top-limb wrap.
    const v5_key = hex("0200000000000000000000000000000000000000000000000000000000000000");
    const v5_msg = hex("ffffffffffffffffffffffffffffffff");
    const v5_tag = hex("03000000000000000000000000000000");

    // #6: s = 2^130−6 exercises the final addition's carry out of 128 bits.
    const v6_key = hex("02000000000000000000000000000000ffffffffffffffffffffffffffffffff");
    const v6_msg = hex("02000000000000000000000000000000");
    const v6_tag = hex("03000000000000000000000000000000");

    // #7 / #8: the two "imperfect carry propagation" vectors.
    const v7_key = hex("0100000000000000000000000000000000000000000000000000000000000000");
    const v7_msg = hex("fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff") ++ hex("11000000000000000000000000000000");
    const v7_tag = hex("05000000000000000000000000000000");

    const v8_key = v7_key;
    const v8_msg = hex("fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe") ++ hex("01010101010101010101010101010101");
    const v8_tag = hex("00000000000000000000000000000000");

    // #9: h = 2^130−6 exactly (no final subtraction).
    const v9_key = hex("0200000000000000000000000000000000000000000000000000000000000000");
    const v9_msg = hex("fdffffffffffffffffffffffffffffff");
    const v9_tag = hex("faffffffffffffffffffffffffffffff");

    // #10 / #11: the long "carry propagation" pair from §A.3.
    const v10_key = hex("0100000000000000040000000000000000000000000000000000000000000000");
    const v10_msg = hex("e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000") ++
        hex("0000000000000000000000000000000001000000000000000000000000000000");
    const v10_tag = hex("14000000000000005500000000000000");

    const v11_key = v10_key;
    const v11_msg = hex("e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000");
    const v11_tag = hex("13000000000000000000000000000000");

    const vectors = [_]A3Vector{
        .{ .key = v1_key, .msg = &v1_msg, .tag = v1_tag },
        .{ .key = v2_key, .msg = v2_msg, .tag = v2_tag },
        .{ .key = v3_key, .msg = v3_msg, .tag = v3_tag },
        .{ .key = v4_key, .msg = v4_msg, .tag = v4_tag },
        .{ .key = v5_key, .msg = &v5_msg, .tag = v5_tag },
        .{ .key = v6_key, .msg = &v6_msg, .tag = v6_tag },
        .{ .key = v7_key, .msg = &v7_msg, .tag = v7_tag },
        .{ .key = v8_key, .msg = &v8_msg, .tag = v8_tag },
        .{ .key = v9_key, .msg = &v9_msg, .tag = v9_tag },
        .{ .key = v10_key, .msg = &v10_msg, .tag = v10_tag },
        .{ .key = v11_key, .msg = &v11_msg, .tag = v11_tag },
    };

    inline for (widths) |L| {
        for (vectors, 1..) |v, n| {
            var tag: [16]u8 = undefined;
            Generic(L).create(&tag, v.msg, &v.key);
            testing.expectEqualSlices(u8, &v.tag, &tag) catch |e| {
                std.debug.print("A.3 vector #{d} failed at L={d}\n", .{ n, L });
                return e;
            };
        }
    }
}

test "differential vs std over every length 0..=2048, every lane width" {
    // The partial-final-block path and the lane-boundary straddle are where
    // parallel Poly1305 breaks, so sweep EVERY length rather than sampling
    // edges: this covers 0, 1, one block, one block + 1, exactly N blocks for
    // N ∈ {1,2,4,8}, N blocks + partial, and — crucially — every length on both
    // sides of `wide_min_bytes` for every width, up to many whole lane groups.
    // The upper bound is 2048 so that even L = 8 (whose wide path only starts
    // at 384 bytes) gets a long run of multi-group inputs.
    var prng = std.Random.DefaultPrng.init(0x9E3779B9);
    const rand = prng.random();
    var msg: [2048]u8 = undefined;
    rand.bytes(&msg);
    var key: [32]u8 = undefined;
    rand.bytes(&key);

    inline for (widths) |L| {
        for (0..msg.len + 1) |len| {
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            Generic(L).create(&ours, msg[0..len], &key);
            StdPoly.create(&theirs, msg[0..len], &key);
            testing.expectEqualSlices(u8, &theirs, &ours) catch |e| {
                std.debug.print("length sweep mismatch at len={d}, L={d}\n", .{ len, L });
                return e;
            };
        }
    }
}

test "differential vs std with random keys (carry-chain stress)" {
    // A fixed key exercises one r; random keys probe the carry chain where the
    // deferred-carry bounds are tightest (r near 2^124, limbs near 2^26).
    var prng = std.Random.DefaultPrng.init(0xDEADC0DE);
    const rand = prng.random();
    var msg: [1400]u8 = undefined;
    inline for (widths) |L| {
        for (0..200) |_| {
            var key: [32]u8 = undefined;
            rand.bytes(&key);
            rand.bytes(&msg);
            const len = rand.uintAtMost(usize, msg.len);
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            Generic(L).create(&ours, msg[0..len], &key);
            StdPoly.create(&theirs, msg[0..len], &key);
            try testing.expectEqualSlices(u8, &theirs, &ours);
        }
    }
}

test "all-ones key and message (maximal limbs)" {
    // r clamps to its largest legal value and every message limb is maximal;
    // this is the worst case for the deferred-carry bound.
    const key = @as([32]u8, @splat(0xff));
    var msg: [1024]u8 = undefined;
    @memset(&msg, 0xff);
    inline for (widths) |L| {
        for (0..msg.len + 1) |len| {
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            Generic(L).create(&ours, msg[0..len], &key);
            StdPoly.create(&theirs, msg[0..len], &key);
            try testing.expectEqualSlices(u8, &theirs, &ours);
        }
    }
}

test "streaming update splits agree with one-shot (leftover + pad)" {
    // The AEAD calls update/pad/update/final; every split point must land on
    // the same tag, including splits that leave a partial block straddling a
    // lane group.
    var prng = std.Random.DefaultPrng.init(0x5150);
    const rand = prng.random();
    var msg: [1200]u8 = undefined;
    rand.bytes(&msg);
    var key: [32]u8 = undefined;
    rand.bytes(&key);

    inline for (widths) |L| {
        var one_shot: [16]u8 = undefined;
        Generic(L).create(&one_shot, &msg, &key);
        for (0..msg.len + 1) |split| {
            var st = Generic(L).init(&key);
            st.update(msg[0..split]);
            st.update(msg[split..]);
            var tag: [16]u8 = undefined;
            st.final(&tag);
            testing.expectEqualSlices(u8, &one_shot, &tag) catch |e| {
                std.debug.print("split mismatch at split={d}, L={d}\n", .{ split, L });
                return e;
            };
        }
    }
}

test "pad() after a WIDE run, every lane width" {
    // The test below only ever pads an accumulator the *serial* engine last
    // touched (its `a` is at most 70 bytes). But the AEAD's own shape is
    // `update(ad) / pad / update(ct) / pad / update(lens) / final`, and with AD
    // longer than `wide_min_bytes` the pad lands directly on an accumulator the
    // vector engine just wrote back — a seam nothing else exercises.
    var prng = std.Random.DefaultPrng.init(0xBEEF_5A5A);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    rand.bytes(&key);
    var a: [1500]u8 = undefined;
    var b: [1500]u8 = undefined;
    rand.bytes(&a);
    rand.bytes(&b);

    const lens = [_]usize{ 176, 177, 191, 192, 193, 255, 256, 383, 384, 385, 512, 1024, 1500 };
    inline for (widths) |L| {
        for (lens) |n| {
            for (lens) |m| {
                var ours = Generic(L).init(&key);
                ours.update(a[0..n]);
                ours.pad();
                ours.update(b[0..m]);
                ours.pad();
                ours.update(a[0..17]);
                var ot: [16]u8 = undefined;
                ours.final(&ot);

                var theirs = StdPoly.init(&key);
                theirs.update(a[0..n]);
                theirs.pad();
                theirs.update(b[0..m]);
                theirs.pad();
                theirs.update(a[0..17]);
                var tt: [16]u8 = undefined;
                theirs.final(&tt);

                testing.expectEqualSlices(u8, &tt, &ot) catch |e| {
                    std.debug.print("pad-after-wide mismatch L={d} n={d} m={d}\n", .{ L, n, m });
                    return e;
                };
            }
        }
    }
}

test "pad() matches std's pad() across leftover states" {
    var prng = std.Random.DefaultPrng.init(0xFEED_BEEF);
    const rand = prng.random();
    // `a` sweeps every leftover state; `b` is long enough that the input after
    // the pad still reaches the wide path at every width.
    var a: [70]u8 = undefined;
    var b: [900]u8 = undefined;
    rand.bytes(&a);
    rand.bytes(&b);
    var key: [32]u8 = undefined;
    rand.bytes(&key);

    inline for (widths) |L| {
        for (0..a.len + 1) |n| {
            var ours = Generic(L).init(&key);
            ours.update(a[0..n]);
            ours.pad();
            ours.update(&b);
            var ot: [16]u8 = undefined;
            ours.final(&ot);

            var theirs = StdPoly.init(&key);
            theirs.update(a[0..n]);
            theirs.pad();
            theirs.update(&b);
            var tt: [16]u8 = undefined;
            theirs.final(&tt);

            try testing.expectEqualSlices(u8, &tt, &ot);
        }
    }
}

// THE ONLY TEST THAT CAN FAIL ON A WRONG `wide_min_groups`.
//
// The lane-parallel engine is byte-identical to the serial one by design, so
// no differential, KAT, sweep or fuzz case in this file can tell whether it
// ran. Without this test the threshold could be raised to 4096 groups — i.e.
// the vector engine switched off at every size this module will ever see —
// with `zig build test-chachapoly` still reporting exit 0 and every test
// green, while the MAC quietly dropped from 2.47× std to 1.06×.
//
// The byte counts below are **literals**, deliberately. Written as
// `wide_min_bytes - 1` / `wide_min_bytes` they would re-assert whatever the
// constant happens to be and stay green for any value of it — which is the
// exact defect this test exists to close, one level up.
test "wide_min_groups routes each length to the engine it was measured for" {
    // `wide_min_bytes = 16 · L · wide_min_groups`, so with the shipped
    // `wide_min_groups = 3` the first length that reaches the vector engine is
    // 48·L: 96 B at L=2, 192 B at L=4, 384 B at L=8. A single `update` of one
    // byte less must stay entirely on std's serial core.
    try testing.expectEqual(@as(usize, 3), Generic(4).wide_min_groups);
    try testing.expectEqual(@as(usize, 96), Generic(2).wide_min_bytes);
    try testing.expectEqual(@as(usize, 192), Generic(4).wide_min_bytes);
    try testing.expectEqual(@as(usize, 384), Generic(8).wide_min_bytes);

    const key = @as([32]u8, @splat(0x7C));
    var msg: [1024]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 97);
    var tag: [16]u8 = undefined;
    var ref: [16]u8 = undefined;

    const Case = struct { L: usize, len: usize, want: Path, why: []const u8 };
    inline for ([_]Case{
        // L = 2 — threshold 96 bytes
        .{ .L = 2, .len = 95, .want = .serial_std, .why = "one below" },
        .{ .L = 2, .len = 96, .want = .wide, .why = "at the threshold" },
        .{ .L = 2, .len = 512, .want = .wide, .why = "well past it" },
        // L = 4 — threshold 192 bytes (the shipped width on any AVX2 host)
        .{ .L = 4, .len = 32, .want = .serial_std, .why = "short packet" },
        .{ .L = 4, .len = 191, .want = .serial_std, .why = "one below" },
        .{ .L = 4, .len = 192, .want = .wide, .why = "at the threshold" },
        .{ .L = 4, .len = 1024, .want = .wide, .why = "well past it" },
        // L = 8 — the shipped width on AVX2 and AVX-512: the 4-lane half
        // engine from 192 bytes, the 8-lane one from 384
        .{ .L = 8, .len = 191, .want = .serial_std, .why = "one below the half engine" },
        .{ .L = 8, .len = 192, .want = .wide_half, .why = "at the half threshold" },
        .{ .L = 8, .len = 383, .want = .wide_half, .why = "one below" },
        .{ .L = 8, .len = 384, .want = .wide, .why = "at the threshold" },
        // L = 4 has no half engine: below 192 is serial (above), at it wide.
        // L = 1 has no wide engine at all, at any length.
        .{ .L = 1, .len = 1024, .want = .serial_std, .why = "no vector engine" },
    }) |c| {
        mac_path = .serial_std;
        Generic(c.L).create(&tag, msg[0..c.len], &key);
        testing.expectEqual(c.want, mac_path) catch |e| {
            std.debug.print(
                "L={d}: {d} B ({s}) routed to {s}\n",
                .{ c.L, c.len, c.why, @tagName(mac_path) },
            );
            return e;
        };
        // The routing assertion above would also pass on a call that computed
        // nothing, so pin the bytes too — against std, the independent oracle.
        StdPoly.create(&ref, msg[0..c.len], &key);
        try testing.expectEqualSlices(u8, &ref, &tag);
    }
}

test "a partial block topped up by update still reaches the wide engine" {
    // `update` first fills a pending partial block through std, then hands the
    // rest to the vector engine if it is still long enough. The routing test
    // above only ever starts on a block boundary (`create`), so a top-up that
    // over-filled — leaving `leftover != 0` — kept every later bulk on the
    // serial core with every byte still equal (mutation run 2026-10-04,
    // survivor). Here the bulk after a 1/5/15-byte head is far past
    // `wide_min_bytes` at every width, so it must run wide.
    const key = @as([32]u8, @splat(0x3D));
    var msg: [1024]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 131);
    inline for (.{ 2, 4, 8 }) |L| {
        for ([_]usize{ 1, 5, 15 }) |head| {
            var st = Generic(L).init(&key);
            st.update(msg[0..head]);
            mac_path = .serial_std;
            st.update(msg[head..]);
            testing.expectEqual(Path.wide, mac_path) catch |e| {
                std.debug.print("L={d}: bulk after a {d}-byte head stayed serial\n", .{ L, head });
                return e;
            };
            var tag: [16]u8 = undefined;
            st.final(&tag);
            var ref: [16]u8 = undefined;
            StdPoly.create(&ref, &msg, &key);
            try testing.expectEqualSlices(u8, &ref, &tag);
        }
    }
}

test "final wipes the key-derived power table it built" {
    // std's `final` wipes only `inner`. The r^1..r^L table — r^L, 5·r^L and
    // both lane-fold vectors — lives outside it and is as secret as the key,
    // and `final`'s own comment promises it is cleared. Nothing asserted that:
    // dropping any one of the four wipes, or all of them, stayed green
    // (mutation run 2026-10-04). 512 bytes reaches the wide path at every
    // width, so the table is built before `final` runs.
    const key = @as([32]u8, @splat(0xA7));
    var msg: [512]u8 = undefined;
    @memset(&msg, 0x5C);
    inline for (.{ 2, 4, 8 }) |L| {
        var st = Generic(L).init(&key);
        st.update(&msg);
        try testing.expect(st.powers_ready);
        var tag: [16]u8 = undefined;
        st.final(&tag);
        try testing.expect(!st.powers_ready);
        for (st.rl) |w| try testing.expectEqual(@as(u32, 0), w);
        for (st.sl) |w| try testing.expectEqual(@as(u32, 0), w);
        for (mem.asBytes(&st.rp)) |b| try testing.expectEqual(@as(u8, 0), b);
        for (mem.asBytes(&st.sp)) |b| try testing.expectEqual(@as(u8, 0), b);
        if (Generic(L).H > 0) {
            for (st.rh) |w| try testing.expectEqual(@as(u32, 0), w);
            for (st.sh) |w| try testing.expectEqual(@as(u32, 0), w);
            for (mem.asBytes(&st.rph)) |b| try testing.expectEqual(@as(u8, 0), b);
            for (mem.asBytes(&st.sph)) |b| try testing.expectEqual(@as(u8, 0), b);
        }
    }
}

test "the half engine's power table is the full table's prefix" {
    // The half engine steps by r^H and folds by r^H..r^1, all cut from the one
    // r^1..r^L table. A wrong index there (r^(H+1), an off-by-one fold) fails
    // the byte comparisons only at the lengths that take the half engine, so
    // pin those lengths against std here, with a partial head, at L = 8.
    const key = @as([32]u8, @splat(0xE1));
    var msg: [400]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 53 +% 7);
    for ([_]usize{ 192, 200, 255, 256, 320, 383 }) |len| {
        for ([_]usize{ 0, 3 }) |head| {
            var st = Generic(8).init(&key);
            st.update(msg[0..head]);
            mac_path = .serial_std;
            st.update(msg[head..len]);
            // A head leaves a partial block; `update` tops it up to 16 bytes
            // first, so the bulk the engines see is `len − 16`.
            const bulk = if (head == 0) len else len - 16;
            const want: Path = if (bulk >= 192) .wide_half else .serial_std;
            try testing.expectEqual(want, mac_path);
            var tag: [16]u8 = undefined;
            st.final(&tag);
            var ref: [16]u8 = undefined;
            StdPoly.create(&ref, msg[0..len], &key);
            try testing.expectEqualSlices(u8, &ref, &tag);
        }
    }
}

test "exportAcc drains a limb the first carry pass leaves at exactly 2^26" {
    // `exportAcc` promises to normalise its input fully before packing, and the
    // packing ORs `f[1] << 26` next to `f[2] << 52` — so an undrained limb 1
    // overlaps limb 2's low bit and silently loses 2^52. One carry pass can
    // leave limb 1 at 2^26 (the top limb's `5·c` wrap re-carries into it); the
    // second pass is what drains it. In the shipped pipeline the input already
    // went through `carryLimbs`, so dropping that second pass stayed green
    // (mutation run 2026-10-04) — this pins the function's own contract instead
    // of the redundancy around it.
    //
    // Limbs x0 = x1 = 2^26 − 1, x2 = 1, x3 = 0, x4 = 2^26. Modulo
    // p = 2^130 − 5, x4·2^104 = 2^130 ≡ 5, so
    //   x ≡ (2^26 − 1) + (2^26 − 1)·2^26 + 1·2^52 + 5 = 2^53 + 4,
    // which is `h = { 2^53 + 4, 0, 0 }` in std's `[3]u64` accumulator.
    const h = Generic(4).exportAcc(.{ limb_mask, limb_mask, 1, 0, 1 << 26 });
    try testing.expectEqual([3]u64{ (1 << 53) + 4, 0, 0 }, h);
}

test "selected lane count matches the target's features" {
    // Documents (and pins) the comptime selection: no runtime dispatch.
    if (builtin.cpu.has(.x86, .avx512f) or builtin.cpu.has(.x86, .avx2)) {
        try testing.expectEqual(@as(usize, 8), lanes);
    } else {
        try testing.expectEqual(@as(usize, 1), lanes);
        try testing.expect(Poly1305 == StdPoly);
    }
    try testing.expectEqual(simd_active, lanes > 1);
}

/// `testkit.fuzz.seedHex` — see that module for why a corpus entry is not the
/// frame.
const polySeed = @import("testkit").fuzz.seedHex;

/// The key occupies the first 32 octets of every drawn slice; the message is
/// everything after it. Spelled out here because it is the layout the corpus
/// below is written in.
const poly_key_len = 32;

/// `key(32) ‖ message` tuples in the format `Smith.slice` reads.
///
/// ⚠ The lengths are the point. `wide_min_groups` routes a message to the
/// scalar or the wide engine by length, and the RFC 8439 §A.3 vectors exist
/// precisely because a parallel implementation breaks on the carry chain — so
/// the corpus carries the block boundaries (0, 1, 15, 16, 17), a full wide
/// group, and the far end of the harness's 640-octet buffer.
const poly_seeds = [_][]const u8{
    // RFC 8439 §2.5.2's worked example: key, then "Cryptographic Forum Research Group".
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b" ++
        "43727970746f6772617068696320466f72756d2052657365617263682047726f7570"),
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"), // the empty message
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b" ++ "41"), // one octet
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b" ++ strRepeat("AA", 15)), // one short of a block
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b" ++ strRepeat("AA", 16)), // exactly one block
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b" ++ strRepeat("AA", 17)), // one block plus a leftover
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b" ++ strRepeat("AA", 128)), // a wide run
    polySeed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b" ++ strRepeat("AA", 608)), // the full 640-octet buffer
    polySeed(strRepeat("00", 32) ++ strRepeat("AA", 64)), // an all-zero key: r = 0, every product vanishes
    polySeed(strRepeat("ff", 32) ++ strRepeat("ff", 64)), // all-ones key and message: maximal limbs
    polySeed(strRepeat("02", 32)), // a key with no message at all
};

test "fuzz: MAC agrees with std on arbitrary key/message" {
    try testing.fuzz({}, fuzzAgainstStd, .{ .corpus = &poly_seeds });
}

fn fuzzAgainstStd(_: void, smith: *std.testing.Smith) !void {
    return macHarness(std.testing.Smith, smith, testing.allocator);
}

const fuzz_driver = @import("testkit").fuzz.driver;
const FuzzLabel = enum { empty_message, short_message, wide_message };
var fuzz_reach: [@typeInfo(FuzzLabel).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: FuzzLabel) void {
    fuzz_reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// Generic over its source (`Smith` under `--fuzz`, `fuzz_driver.Rng` under the driver).
fn macHarness(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [poly_key_len + 640]u8 = @splat(0);
    // ⚠ ONE `smith.slice` call, and it is the FIRST draw — the key and the
    // message are both carved out of it. It used to be `smith.bytes(&key)`,
    // then `smith.bytes(&msg)`, then
    // `smith.valueRangeAtMost(u16, 0, 640)`: a ranged `Smith` draw reads eight
    // octets as a little-endian u64 and returns the range MINIMUM when fewer
    // remain, and the two `bytes` calls had already consumed everything. So
    // `len` was 0 on every input and this differential compared the MAC of the
    // EMPTY message under an ALL-ZERO key against std — one input, for ever,
    // and the shortest one the carry chain has. Measured 2026-09-07 over the
    // corpus above: **1 distinct (key, message) pair and 0 message octets
    // before; 11 pairs and 947 octets after.**
    const n: usize = smith.slice(&buf);
    const key: [32]u8 = buf[0..poly_key_len].*;
    const msg: [640]u8 = buf[poly_key_len..].*;
    const len: usize = if (n > poly_key_len) n - poly_key_len else 0;

    if (len == 0) mark(.empty_message) else if (len < 16 * 3 * lanes) mark(.short_message) else mark(.wide_message);
    var ours: [16]u8 = undefined;
    var theirs: [16]u8 = undefined;
    Poly1305.create(&ours, msg[0..len], &key);
    StdPoly.create(&theirs, msg[0..len], &key);
    try testing.expectEqualSlices(u8, &theirs, &ours);
}

test "fuzz driver: CHACHAPOLY_FUZZ (chachapoly-poly1305)" {
    try fuzz_driver.run(macHarness, .{ .prefix = "CHACHAPOLY_FUZZ", .name = "chachapoly-poly1305" });
}

test "fuzz harness: 300 seeds in every test run, and they get everywhere" {
    fuzz_reach = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        macHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("chachapoly-poly1305 seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (fuzz_reach, 0..) |n, i| if (n == 0) {
        // The wide label needs a message of 48 * lanes octets; Rng.slice reaches it.
        std.debug.print("reach: label {t} never hit in 300 seeds\n", .{@as(FuzzLabel, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "corpus: every seed reaches the MAC, and the message coverage is pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum) and nothing else would notice.
    //
    // ⚠ "The MACs agreed" is 100% on a corpus of one empty message — that is
    // exactly the state this target was in. The numbers that carry information
    // are how many DISTINCT (key, message) pairs the corpus drives and how
    // many message octets in total, because both are pinned at their minimum
    // (1 and 0) by the collapsed draw.
    var pairs: usize = 0;
    var octets: usize = 0;
    var wide_runs: usize = 0;
    var seen: [poly_seeds.len][16]u8 = undefined;
    for (poly_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [poly_key_len + 640]u8 = @splat(0);
        const n: usize = smith.slice(&buf);
        const key: [32]u8 = buf[0..poly_key_len].*;
        const msg = buf[poly_key_len..];
        const len: usize = if (n > poly_key_len) n - poly_key_len else 0;
        octets += len;
        if (len >= 16 * 3 * lanes) wide_runs += 1; // `wide_min_groups` = 3, see `Generic`

        var tag: [16]u8 = undefined;
        Poly1305.create(&tag, msg[0..len], &key);
        var std_tag: [16]u8 = undefined;
        StdPoly.create(&std_tag, msg[0..len], &key);
        try testing.expectEqualSlices(u8, &std_tag, &tag);

        var already = false;
        for (seen[0..pairs]) |t| {
            if (std.mem.eql(u8, &t, &tag)) already = true;
        }
        if (!already) {
            seen[pairs] = tag;
            pairs += 1;
        }
    }
    // Measured 2026-09-07: with the collapsing draw, 1 distinct pair (the
    // empty message under an all-zero key) and 0 message octets, eleven times
    // over. After:
    try testing.expectEqual(poly_seeds.len, pairs);
    try testing.expectEqual(@as(usize, 947), octets);
    try testing.expect(wide_runs >= 1);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
