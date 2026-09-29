// SPDX-License-Identifier: MIT
//! ct25519 — scalar multiplication on Edwards25519 / Ristretto255 that is
//! safe for a **SECRET** scalar, because it does not branch on one.
//!
//! ## Why this module exists
//!
//! `std.crypto.ecc.Edwards25519.mul` (and `Ristretto255.mul`, which is a
//! thin wrapper over it) IS internally constant-time — a 4-bit fixed window
//! over a 16-entry precomputed table selected with `Fe.cMov`, 64
//! unconditional iterations whatever the scalar — EXCEPT for one thing: its
//! `pcMul16` ladder ends with
//!
//! ```zig
//! try q.rejectIdentity();   // std/crypto/25519/edwards25519.zig
//! ```
//!
//! which turns "the product is the neutral element" into
//! `error.IdentityElement`. That is a **branch on a scalar-derived value**
//! — and worse, it is contagious: because the function returns an error
//! union, EVERY caller has to branch again to handle it, and the idioms
//! that fall out (`catch continue`, `catch return error.X`,
//! `catch @panic(...)`) make the two paths take visibly different work.
//!
//! When the scalar is a public one (a signature's `s`, a Fiat-Shamir
//! challenge replayed by a verifier) none of that matters and std's `mul`
//! /`mulPublic` are the right call. When the scalar is a **secret** — an
//! OPRF blind, a private key, a DH ratchet scalar, a proof nonce, a
//! blinding factor — the branch reveals whether that secret was zero, and
//! the caller-side branch that follows it can reveal far more.
//!
//! `mul` below is std's own ladder with the trailing rejection removed: the
//! neutral element is returned as an ordinary **value**. There is no error
//! union, so no call site can branch on the scalar, and the control flow
//! (precompute, then 64 window iterations, each an unconditional 15-entry
//! `cMov` select + add + 4 doublings) is identical for every scalar
//! including zero.
//!
//! Same algorithm, same table size, same iteration count as std — so the
//! same cost. This is not a faster multiply and not a different one; it is
//! the same multiply with a leak taken out of its tail.
//!
//! ## What this module deliberately does NOT do
//!
//! - **No identity rejection on the output.** That is the whole point. If a
//!   protocol genuinely needs "the result must not be the neutral element",
//!   it has to establish that from its inputs (see below) rather than by
//!   branching on the output.
//! - **No `WeakPublicKey` rejection on the input point.** std's `mul`
//!   checks `pc[4]` for a small-order base and errors; that is a branch on
//!   the POINT, which in every caller here is public wire data, but it is
//!   still an error union this module refuses to have. **The caller
//!   validates the point.** For ristretto255 that is free: the group is of
//!   PRIME order `L`, so it has no small-order elements at all, and a
//!   decoded `Ristretto255` that is not the identity generates the whole
//!   group. For raw Edwards25519 (cofactor 8) the caller must apply
//!   `rejectLowOrder`/`rejectIdentity` itself where the point is
//!   attacker-supplied — the callers in this repo multiply the fixed base
//!   point, where the question does not arise.
//!
//! Consequence worth stating once, because three callers rely on it: over
//! a prime-order group with a validated non-identity point `P`, the product
//! `s·P` is the identity **iff `s ≡ 0 (mod L)`** — i.e. iff the caller's
//! own secret scalar is degenerate, never because of anything a peer sent.
//! A protocol's "shared secret MUST NOT be the identity" rule is therefore
//! discharged structurally by validating `P` and generating `s` properly,
//! not by a runtime branch on secret-derived data.
//!
//! ## Verification
//!
//! **The tests below are NOT the constant-time oracle.** They compare
//! outputs, and the defect class this module exists to remove — a branch
//! on a secret that changes no output byte — is invisible to all of them:
//! injecting `if (s == 0) return identityElement;` into `mul` leaves
//! `zig build test-ct25519` green. Constant time is checked with a
//! ctgrind-style valgrind run instead; `SPEC.md` carries the harness, the
//! two flags without which it reports a false clean, and the limits of
//! the claim. What the tests DO establish:
//!
//! `mul`/`mulRistretto` are held **bit-exact** against `std`'s own
//! `Edwards25519.mul`/`Ristretto255.mul` wherever std is willing to answer
//! (i.e. every non-degenerate case) over random and edge scalars, on both
//! the base point and random points; RFC 8032 §7.1's published Ed25519
//! public keys are re-derived as `[clamp(H(sk))]B` byte-exactly; and the
//! cases where std refuses (`s = 0`, `s = L`) are pinned to the neutral
//! element as a value. The inputs std refuses *outright* — the identity
//! and an order-8 torsion point, where this module deliberately answers
//! and std returns `error.WeakPublicKey` — are checked against repeated
//! addition, an oracle independent of both ladders; and scalar bits
//! 250..255 are checked against a doubling chain, because every other
//! test here feeds a reduced or clamped scalar in which the top bits are
//! never set. See the tests at the bottom of this file.

const std = @import("std");
const builtin = @import("builtin");

/// Re-exported so callers can name the types without a second std path.
pub const Edwards25519 = std.crypto.ecc.Edwards25519;
pub const Ristretto255 = std.crypto.ecc.Ristretto255;

const Fe = Edwards25519.Fe;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Constant-time-on-secrets scalar multiplication for Edwards25519/Ristretto255 — drops std's secret-dependent `rejectIdentity` branch. Caller must validate points. `X25519` with key generation on the fixed-base comb (2.4× std).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation, no RNG
    .concurrency = .reentrant, // no globals; all types are plain values
    .model_after = "std.crypto.ecc.Edwards25519's own pcMul16 4-bit-window constant-time ladder (std/crypto/25519/edwards25519.zig), with the trailing rejectIdentity removed so the neutral element is a value and the function carries no error union; the ladder itself is the classic fixed-window scalar multiplication of RFC 8032 / Curve25519 implementations",
    .deps = .{},
};

/// `pc[i] = i*p` for `i` in `0..15`, `pc[0]` the neutral element — std's
/// private `Edwards25519.precompute(p, 15)`, which we cannot reach.
fn precompute(p: Edwards25519) [16]Edwards25519 {
    var pc: [16]Edwards25519 = undefined;
    pc[0] = Edwards25519.identityElement;
    pc[1] = p;
    comptime var i: usize = 2;
    inline while (i < 16) : (i += 1) {
        pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
    }
    return pc;
}

/// The base point's table, folded at comptime exactly as std folds its own
/// private `basePointPc` — so `mul(Edwards25519.basePoint, s)` costs the
/// same 64 window iterations and no online precomputation.
const base_pc: [16]Edwards25519 = pc: {
    @setEvalBranchQuota(20_000);
    break :pc precompute(Edwards25519.basePoint);
};

/// Branch-free select of `pc[slot]` (`slot == 0` selects the neutral
/// element), mirroring std's private `Edwards25519.pcSelect`: every entry
/// is touched with a `cMov` whose mask is `1` exactly when `slot ^ i == 0`.
///
/// The mask is `((slot ^ i) -% 1) >> 8`: `slot ^ i` is in `0..15`, so
/// `-% 1` borrows to `~0` only for `slot == i`, and the shift keeps bit 0
/// of that. The `>> 8` is what makes the borrow visible without a compare;
/// `>> 9` and above happen to be equivalent on a 64-bit `usize`, so a
/// mutation there is not a fault injection — mutate the `& 1` or the `-% 1`
/// instead if you want to see this select break.
fn pcSelect(pc: *const [16]Edwards25519, slot: u4) Edwards25519 {
    var t = Edwards25519.identityElement;
    comptime var i: u8 = 1;
    inline while (i < 16) : (i += 1) {
        const c: u64 = ((@as(usize, @as(u8, slot) ^ i) -% 1) >> 8) & 1;
        Fe.cMov(&t.x, pc[i].x, c);
        Fe.cMov(&t.y, pc[i].y, c);
        Fe.cMov(&t.z, pc[i].z, c);
        Fe.cMov(&t.t, pc[i].t, c);
    }
    return t;
}

/// `s * p` on Edwards25519, **constant-time in `s` and total**, with the
/// neutral element returned as an ordinary value rather than raised as
/// `error.IdentityElement`. Safe for a SECRET `s`.
///
/// `s` is used as-is (no clamping, no reduction) — the same contract as
/// std's `Edwards25519.mul`. **All 256 bits are read**: the top window sits
/// at `pos = 252` and covers bits 252..255, so an unreduced `s` yields
/// `s·P` for the full 256-bit integer, NOT for `s mod L`. A protocol that
/// needs the reduced value must reduce first (`scalar.reduce`/`reduce64`),
/// exactly as it must for std. (This comment previously said "only the low
/// 253 bits are read", which was false; the audit's `I2` fault injection —
/// masking bit 255 off inside `mul` — left the whole suite green, because
/// every scalar the tests used was either reduced mod `L` or clamped.)
///
/// The input point is NOT validated: see the module doc comment. Use
/// std's `mulPublic`/`mulDoubleBasePublic` when `s` is public and speed
/// matters — those are variable-time by design and correct there.
pub fn mul(p: Edwards25519, s: [32]u8) Edwards25519 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    const pc = if (p.is_base) base_pc else precompute(p);
    var q = Edwards25519.identityElement;
    var pos: usize = 252;
    while (true) : (pos -= 4) {
        const slot: u4 = @truncate(sc[pos >> 3] >> @as(u3, @truncate(pos)));
        q = q.add(pcSelect(&pc, slot));
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    return q;
}

// ── fixed-base comb (audit C3, a DECISIONS.md P5 algorithm change) ────────
//
// `mul(basePoint, s)` spends 71 % of its time in 252 doublings (audit C3:
// 34.4 of 48.2 µs), because the base point runs the same 16-entry window
// ladder as an arbitrary point. `mulBase`/`mulRistrettoBase` instead use the
// fixed-base comb of Bernstein, Duif, Lange, Schwabe and Yang, "High-speed
// high-security signatures" (CHES 2011, J. Cryptogr. Eng. 2012) §4 — the
// algorithm of ref10's `ge_scalarmult_base`, which libsodium ships as
// `ge25519_scalarmult_base`:
//
//   * recode `s` into signed radix-16 digits `e[0..64]`, each in `[-8, 7]`,
//     so `s = Σ e[i]·16^i + carry·16^64`;
//   * `comb_table[j][k] = (k+1)·16^(2j)·B` for `j < 32`, `k < 8`;
//   * `q = Σ_{i odd} e[i]·16^(i-1)·B`, then `q = 16·q` (4 doublings), then
//     add `Σ_{i even} e[i]·16^i·B` — 64 additions and 4 doublings instead of
//     64 additions and 252 doublings.
//
// ⚠ ONE DELIBERATE DIFFERENCE FROM ref10. ref10 requires `s[31] <= 127` (its
// top digit absorbs the carry and must stay in `[-8, 8]`). This module's
// contract is that **all 256 bits are read** (see `mul`), so the carry out of
// digit 63 is kept as its own secret bit and one extra, always-performed add
// selects between the identity and the constant `2^256·B` (`comb_carry`).
//
// Constant time: the digit loop runs 64 times whatever `s` is; the digit
// recoding is shift/mask arithmetic; each table row is gathered by a
// full-row `cMov` scan (the same mask shape as `pcSelect`) and the sign by a
// `cMov` onto the negated coordinates; the carry add is unconditional.
// Table indices are loop counters only. The source is not the evidence —
// `ctgrind_harness.zig`'s `comb` target is (SPEC.md § "C3").

const comb_rows = 32;
const comb_teeth = 8;
const CombTable = [comb_rows][comb_teeth]Edwards25519;

/// `[j][k] = (k+1)·16^(2j)·B`, extended coordinates, folded at comptime —
/// plus `2^256·B` for the recoding carry. 32·(7 multiples + 8 doublings to
/// the next row) ≈ 480 point operations at comptime, the same shape as
/// `k256`'s and `p256`'s `buildCombTable`.
const comb = blk: {
    @setEvalBranchQuota(100_000_000);
    var tab: CombTable = undefined;
    var row_base = Edwards25519.basePoint;
    row_base.is_base = false;
    for (0..comb_rows) |j| {
        tab[j][0] = row_base;
        for (1..comb_teeth) |k| {
            const m = k + 1; // multiple held in tab[j][k]
            tab[j][k] = if (m % 2 == 0) tab[j][m / 2 - 1].dbl() else tab[j][k - 1].add(row_base);
        }
        // next row: 256·row_base = 32·(8·row_base)
        var nb = tab[j][comb_teeth - 1];
        for (0..5) |_| nb = nb.dbl();
        row_base = nb;
    }
    // After the last row `row_base` is 16^64·B = 2^256·B.
    break :blk .{ .table = tab, .carry = row_base };
};
const comb_table: CombTable = comb.table;
const comb_carry: Edwards25519 = comb.carry;

/// Signed radix-16 recoding of the full 256-bit `s`: `e[i]` in `[-8, 7]`
/// and the returned carry in `{0, 1}`, with `s = Σ e[i]·16^i + carry·16^64`.
/// Branch-free: `x = nibble + carry` is in `0..16`, `(x + 8) >> 4` is 1
/// exactly when `x >= 8`, and subtracting `16·carry` lands `x` in `[-8, 7]`.
fn combRecode(s: *const [32]u8, e: *[64]i8) u8 {
    var carry: u8 = 0;
    for (e, 0..) |*d, i| {
        const nibble: u8 = (s[i >> 1] >> @as(u3, @intCast(4 * (i & 1)))) & 15;
        const x: u8 = nibble + carry; // 0..16
        carry = (x + 8) >> 4;
        d.* = @bitCast(x -% (carry << 4));
    }
    return carry;
}

/// `e·row[0]` for a signed digit `e` in `[-8, 8]`, touching every entry of
/// the row: `|e|` selects by a full `cMov` scan (`|e| == 0` leaves the
/// identity), then the sign selects `-x`/`-t` by `cMov`. ref10's
/// `negative`/`babs`/`equal` shape.
fn combSelect(row: *const [comb_teeth]Edwards25519, e: i8) Edwards25519 {
    const eu: u8 = @bitCast(e);
    const neg: u8 = eu >> 7; // 1 iff e < 0
    const abs: u8 = eu -% ((0 -% neg) & (eu << 1)); // |e|, 0..8
    var t = Edwards25519.identityElement;
    comptime var k: u8 = 1;
    inline while (k <= comb_teeth) : (k += 1) {
        const c: u64 = ((@as(usize, abs ^ k) -% 1) >> 8) & 1;
        const entry = &row[k - 1];
        Fe.cMov(&t.x, entry.x, c);
        Fe.cMov(&t.y, entry.y, c);
        Fe.cMov(&t.z, entry.z, c);
        Fe.cMov(&t.t, entry.t, c);
    }
    const minus_x = t.x.neg();
    const minus_t = t.t.neg();
    Fe.cMov(&t.x, minus_x, neg);
    Fe.cMov(&t.t, minus_t, neg);
    return t;
}

/// `s·B` by the fixed-base comb; see the section comment above. Every
/// secret-derived buffer it owns is wiped before return.
fn combMulBase(s: *const [32]u8) Edwards25519 {
    var e: [64]i8 = undefined;
    defer std.crypto.secureZero(i8, &e);
    var carry = combRecode(s, &e);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&carry));

    var q = Edwards25519.identityElement;
    var i: usize = 1;
    while (i < 64) : (i += 2) q = q.add(combSelect(&comb_table[i >> 1], e[i]));
    q = q.dbl().dbl().dbl().dbl();
    i = 0;
    while (i < 64) : (i += 2) q = q.add(combSelect(&comb_table[i >> 1], e[i]));

    var c = Edwards25519.identityElement;
    const cm: u64 = carry;
    Fe.cMov(&c.x, comb_carry.x, cm);
    Fe.cMov(&c.y, comb_carry.y, cm);
    Fe.cMov(&c.z, comb_carry.z, cm);
    Fe.cMov(&c.t, comb_carry.t, cm);
    return q.add(c);
}

/// `s * B` on Edwards25519 against the fixed base point, **constant-time in
/// `s` and total** — the same result as `mul(Edwards25519.basePoint, s)` for
/// every 256-bit `s` (all bits read, no reduction), computed with the
/// fixed-base comb above instead of the window ladder (audit C3, ~3× faster;
/// SPEC.md § "C3"). `mul(Edwards25519.basePoint, s)` deliberately stays on
/// the ladder: it is the reference the comb is differentially tested against.
pub fn mulBase(s: [32]u8) Edwards25519 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    return combMulBase(&sc);
}

/// `s * p` over Ristretto255 — `mul` on the underlying Edwards25519 point.
/// Constant-time in `s`, no error union, neutral element as a value.
///
/// ristretto255 is a PRIME-ORDER group, so there is no low-order input to
/// reject and the product is the neutral element iff `s ≡ 0 (mod L)` for a
/// non-identity `p`.
pub fn mulRistretto(p: Ristretto255, s: [32]u8) Ristretto255 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    return .{ .p = mul(p.p, sc) };
}

// ── X25519 key generation on the comb ────────────────────────────────────
//
// `std.crypto.dh.X25519` derives a public key with the Montgomery ladder over
// the base point `u = 9` — 255 ladder steps, the same work as a shared-secret
// computation against a peer's point. A TLS server pays both per handshake
// (ephemeral key pair, then the shared secret), so the base-point half was
// measured at ~28 %/2 of a qap ECDHE handshake's CPU (2026-09-28). The base
// point is fixed, and the fixed-base comb above already computes `s·B` on
// Edwards25519 in a third of the ladder's time; Montgomery `u = 9` IS
// Edwards `B` under the birational map (RFC 7748 §4.1), so the X25519
// public key is `u = (1 + y) / (1 - y)` of the comb's result — in extended
// coordinates `(Z + Y) / (Z - Y)`, one field inversion. std's own
// `Curve25519.fromEdwards25519` does the same map with two inversions.
//
// The scalar is clamped exactly as std clamps it (`scalar.clamp`: bits 0-2
// cleared, bit 255 cleared, bit 254 set), so the public key is bit-exact
// with `std.crypto.dh.X25519.recoverPublicKey` — a differential test below
// holds that over random seeds, and RFC 7748 §6.1's vectors pin it.
//
// Constant time: the comb is the C3-audited path; the map is field
// arithmetic with a fixed-chain `Fe.invert`, and there is NO identity check
// on the result — std's `recoverPublicKey` branches on `rejectIdentity`
// (ctgrind sees it: a third context, `curve25519.zig`), this one does not,
// because the identity is **unreachable for a clamped scalar**:
// `k ∈ [2^254, 2^255)` with `8 | k`, and `k·B = O` iff `L | k`; the only
// multiples of `L` in that range are `4L`..`7L`, none divisible by 8 (`L`
// is odd). The `IdentityElementError` in the signatures is kept so the type
// is a drop-in for std's, whose `KeyPair.generateDeterministic` can fail;
// this module never produces it. ctgrind target `x25519` (SPEC.md § "X25519
// key generation") shows the same two out-of-file contexts as `comb`.

/// `std.crypto.dh.X25519` with key generation on the fixed-base comb.
///
/// Same declarations, lengths and byte formats as std's `X25519`.
/// `recoverPublicKey` — and through it `KeyPair.generateDeterministic` /
/// `generate` — takes the comb. `scalarmult` (the shared secret against a
/// peer's public key) is the RFC 7748 Montgomery ladder on a 4×64-bit field
/// core in x86-64 MULX (BMI2) / ADCX+ADOX (ADX) assembly where the build
/// target has those features, else std's ladder (§ "X25519 shared secret"
/// below, SPEC.md § P6).
pub const X25519 = struct {
    const Std = std.crypto.dh.X25519;

    pub const Curve = Std.Curve;
    pub const secret_length = Std.secret_length;
    pub const public_length = Std.public_length;
    pub const shared_length = Std.shared_length;
    pub const seed_length = Std.seed_length;

    pub const IdentityElementError = std.crypto.errors.IdentityElementError;

    pub const KeyPair = struct {
        public_key: [public_length]u8,
        secret_key: [secret_length]u8,

        /// Deterministically derive a key pair from a cryptographically
        /// secure secret seed — std's `generateDeterministic`, on the comb.
        pub fn generateDeterministic(seed: [seed_length]u8) IdentityElementError!KeyPair {
            return .{
                .public_key = try X25519.recoverPublicKey(seed),
                .secret_key = seed,
            };
        }

        /// Generate a new, random key pair.
        pub fn generate(io: std.Io) KeyPair {
            var random_seed: [seed_length]u8 = undefined;
            while (true) {
                io.random(&random_seed);
                return generateDeterministic(random_seed) catch {
                    @branchHint(.unlikely);
                    continue;
                };
            }
        }
    };

    /// Compute the public key for a given private key — `clamp(sk)·B` as the
    /// Montgomery `u`-coordinate, byte-exact with std's `recoverPublicKey`.
    pub fn recoverPublicKey(secret_key: [secret_length]u8) IdentityElementError![public_length]u8 {
        var sc = secret_key;
        defer std.crypto.secureZero(u8, &sc);
        Edwards25519.scalar.clamp(&sc);
        const q = combMulBase(&sc);
        // u = (1 + y) / (1 - y) with y = Y / Z, i.e. (Z + Y) / (Z - Y). No
        // identity branch: unreachable for a clamped scalar (see above).
        return q.z.add(q.y).mul(q.z.sub(q.y).invert()).toBytes();
    }

    /// Compute the X25519 shared secret — byte-exact with std's `scalarmult`,
    /// including `error.IdentityElement` for an all-zero result (which, for
    /// a clamped scalar, happens iff `public_key` is a small-order point).
    /// The backend is fixed at compile time: `x25519_backend`.
    pub fn scalarmult(secret_key: [secret_length]u8, public_key: [public_length]u8) IdentityElementError![shared_length]u8 {
        const b: X25519Backend = if (builtin.is_test) (test_hooks.forced orelse x25519_backend) else x25519_backend;
        switch (b) {
            .stdlib => return Std.scalarmult(secret_key, public_key),
            .mulx => if (comptime fe64.bmi2) return sharedSecret(false, secret_key, public_key) else unreachable,
            .mulx_adx => if (comptime fe64.adx) return sharedSecret(true, secret_key, public_key) else unreachable,
        }
    }
};

// ── X25519 shared secret: a 4×64-bit field core in MULX/ADX assembly (P6) ─
//
// qap's TLS churn lane (2026-09-29) had the shared-secret ladder as its
// largest single item, 18.65 % of CPU. std's field is 5×51-bit limbs with
// u128 products (25 multiplies per field multiplication); on x86-64 with
// BMI2 the natural representation is 4×64-bit limbs, 16 `mulx` per
// multiplication and 10 per squaring, with the 512-bit product folded by
// `2^256 ≡ 38 (mod p)`. This is the representation of the published x86-64
// Curve25519 work (Oliveira, López, Hışıl, Faz-Hernández, Rodríguez-
// Henríquez, "How to (pre-)compute a ladder", SAC 2017; Nath & Sarkar,
// "Efficient arithmetic in (pseudo-)Mersenne prime order fields", 2018) and
// is implemented here from that description and from RFC 7748 §5 — no code
// from any implementation was read or transcribed (SPEC.md § P6,
// provenance).
//
// Representation: `[4]u64`, little-endian limbs, value in `[0, 2^256)`,
// only CONGRUENT mod p = 2^255 − 19 — never reduced below p until `toBytes`.
// Every operation maps `[0, 2^256)` into `[0, 2^256)`; there is no
// intermediate bound to track, which is what makes the arithmetic total.
//
// Constant time: every asm block is straight-line (no jump; every address
// is the one state pointer plus a compile-time offset), and uses only
// `mov`, `add`/`adc`/`sub`/`sbb`, `adcx`/`adox`, `mulx`, `imul` by a
// constant, `and`, `xor` — instruction classes Intel lists as having data-
// operand-independent timing. That is a statement about the instructions,
// not a guarantee about any microarchitecture (SPEC.md § Threat model).
// Conditional folds of a carry are a mask (`sbb r,r; and $38,r`), never a
// branch. The ladder swap is an xor mask; the inversion is a fixed Fermat
// chain. Evidence: ctgrind target `x25519` (SPEC.md § P6), not this comment.

/// Which implementation computes `X25519.scalarmult`.
const X25519Backend = enum {
    /// `std.crypto.dh.X25519.scalarmult`, unchanged.
    stdlib,
    /// 4×64-bit field, `mulx` with single `adc` carry chains (BMI2).
    mulx,
    /// 4×64-bit field, `mulx` with two carry chains `adcx`/`adox` (BMI2+ADX).
    mulx_adx,
};

/// The backend `X25519.scalarmult` uses in this build (tests read it as
/// `test_hooks.default`): fixed at compile
/// time from the target's CPU features, and only where the LLVM backend
/// emits the code (the self-hosted x86 backend is for the edit loop only,
/// `.claude/rules/zig-pitfalls.md`). A baseline `x86_64` target — or any
/// other architecture — gets std's ladder.
const x25519_backend: X25519Backend = if (fe64.adx) .mulx_adx else if (fe64.bmi2) .mulx else .stdlib;

/// Test-only: force a backend so one test run holds every compiled path to
/// std. Empty outside `zig test`, so no production path can read it.
pub const test_hooks = if (builtin.is_test) struct {
    pub var forced: ?X25519Backend = null;

    /// The backend this build dispatches to when nothing is forced.
    pub const default = x25519_backend;

    /// Whether `b` is compiled into this build.
    pub fn available(b: X25519Backend) bool {
        return switch (b) {
            .stdlib => true,
            .mulx => fe64.bmi2,
            .mulx_adx => fe64.adx,
        };
    }
} else struct {};

/// RFC 7748 §5 `X25519(k, u)` on the 4×64 field, then std's all-zero check.
fn sharedSecret(comptime adx: bool, secret_key: [32]u8, public_key: [32]u8) std.crypto.errors.IdentityElementError![32]u8 {
    var k = secret_key;
    defer std.crypto.secureZero(u8, &k);
    Edwards25519.scalar.clamp(&k); // std's clamp: bits 0-2 and 255 cleared, 254 set
    const out = ladder(adx, &k, &public_key);
    // std returns `error.IdentityElement` when the result is zero, and the
    // shape is kept. The zero flag is computed without a branch; the one
    // branch is on that flag, which is a function of the PUBLIC point alone:
    // a clamped `k` is `8·m` with `k ∈ [2^254, 2^255)`, so `k·P = O` iff the
    // order of `P` divides 8 (curve) or 4 (twist) — the prime-order parts `L`
    // and `L'` cannot divide `k` (`8L`, `4L'` fall outside the range or are
    // not multiples of 8; SPEC.md § P6). It is therefore declassified for
    // memcheck (a no-op without `-fvalgrind`), so the ctgrind harness keeps
    // measuring the secret instead of flagging an RFC 7748 §6.1 check.
    var acc: u8 = 0;
    for (out) |byte| acc |= byte;
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&acc));
    if (acc == 0) return error.IdentityElement;
    return out;
}

/// The Montgomery ladder of RFC 7748 §5 over bits 254..0 of the clamped `k`
/// (bit 255 is zero after clamping — std's `ladder(p, s, 255)` does the same
/// 255 steps), `u` with its top bit masked.
fn ladder(comptime adx: bool, k: *const [32]u8, u: *const [32]u8) [32]u8 {
    const F = fe64.Ops(adx);
    var st: fe64.State = undefined;
    st[@intFromEnum(fe64.Slot.x1)] = fe64.fromBytes(u);
    st[@intFromEnum(fe64.Slot.x2)] = .{ 1, 0, 0, 0 };
    st[@intFromEnum(fe64.Slot.z2)] = .{ 0, 0, 0, 0 };
    st[@intFromEnum(fe64.Slot.x3)] = st[@intFromEnum(fe64.Slot.x1)];
    st[@intFromEnum(fe64.Slot.z3)] = .{ 1, 0, 0, 0 };
    var swap: u64 = 0;
    var t: usize = 255;
    while (t > 0) {
        t -= 1;
        const bit: u64 = (k[t >> 3] >> @as(u3, @truncate(t))) & 1;
        swap ^= bit;
        fe64.cswap(swap, &st, .x2, .x3);
        fe64.cswap(swap, &st, .z2, .z3);
        swap = bit;
        F.add(&st, .a, .x2, .z2); // A = x2 + z2
        F.sq(&st, .aa, .a); // AA = A²
        F.sub(&st, .b, .x2, .z2); // B = x2 − z2
        F.sq(&st, .bb, .b); // BB = B²
        F.sub(&st, .e, .aa, .bb); // E = AA − BB
        F.add(&st, .c, .x3, .z3); // C = x3 + z3
        F.sub(&st, .d, .x3, .z3); // D = x3 − z3
        F.fmul(&st, .da, .d, .a); // DA = D·A
        F.fmul(&st, .cb, .c, .b); // CB = C·B
        F.add(&st, .t, .da, .cb);
        F.sq(&st, .x3, .t); // x3 = (DA + CB)²
        F.sub(&st, .t, .da, .cb);
        F.sq(&st, .t, .t);
        F.fmul(&st, .z3, .x1, .t); // z3 = x1·(DA − CB)²
        F.fmul(&st, .x2, .aa, .bb); // x2 = AA·BB
        F.mul121665(&st, .t, .e);
        F.add(&st, .t, .aa, .t);
        F.fmul(&st, .z2, .e, .t); // z2 = E·(AA + a24·E)
    }
    fe64.cswap(swap, &st, .x2, .x3);
    fe64.cswap(swap, &st, .z2, .z3);
    F.invert(&st, .zi, .z2);
    F.fmul(&st, .r, .x2, .zi);
    return fe64.toBytes(&st[@intFromEnum(fe64.Slot.r)]);
}

/// GF(2^255 − 19) on four 64-bit limbs; see the section comment above.
const fe64 = struct {
    const Limbs = [4]u64;

    /// Inline asm only where LLVM emits it — never the self-hosted backend.
    const x86_asm = builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm;
    const bmi2 = x86_asm and std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);
    const adx = bmi2 and std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

    /// Every field element the ladder and the inversion touch lives in ONE
    /// array, and an operation names its operands by slot: the asm then
    /// needs a single base register and addresses each operand at a
    /// compile-time offset from it. Three pointer operands plus the eleven
    /// registers the multiplication uses do not fit once LLVM reserves a
    /// frame/base pointer (ReleaseFast: "inline assembly requires more
    /// registers than available").
    const Slot = enum(u8) {
        x1,
        x2,
        z2,
        x3,
        z3,
        a,
        aa,
        b,
        bb,
        e,
        c,
        d,
        da,
        cb,
        t,
        zi,
        r, // ladder
        v2,
        v9,
        v11,
        v5,
        v10,
        v20,
        v40,
        v50,
        v100,
        v200,
        v250, // inversion chain
        p,
        q, // tests only
    };
    const State = [@typeInfo(Slot).@"enum".fields.len]Limbs;

    /// RFC 7748 §5 decodeUCoordinate: little-endian, top bit masked. A value
    /// in `[p, 2^255)` is kept as is — it is congruent, which is all the
    /// arithmetic needs.
    fn fromBytes(s: *const [32]u8) Limbs {
        return .{
            std.mem.readInt(u64, s[0..8], .little),
            std.mem.readInt(u64, s[8..16], .little),
            std.mem.readInt(u64, s[16..24], .little),
            std.mem.readInt(u64, s[24..32], .little) & 0x7fff_ffff_ffff_ffff,
        };
    }

    /// Fully reduce `[0, 2^256)` to `[0, p)` and encode — branch-free.
    fn toBytes(a: *const Limbs) [32]u8 {
        // v = a mod 2^255 + 19·a[255]  ∈ [0, 2^255 + 19)
        const top = a[3] >> 63;
        var v: u256 = @as(u256, a[3] & 0x7fff_ffff_ffff_ffff) << 192 |
            @as(u256, a[2]) << 128 | @as(u256, a[1]) << 64 | a[0];
        v += (0 -% top) & 19;
        // v ≥ p  ⇔  bit 255 of v + 19 is set; then the answer is v + 19 − 2^255.
        const w = v + 19;
        const ge: u256 = 0 -% (w >> 255);
        const r = ((w & ~(@as(u256, 1) << 255)) & ge) | (v & ~ge);
        var out: [32]u8 = undefined;
        std.mem.writeInt(u256, &out, r, .little);
        return out;
    }

    /// Swap slots `a` and `b` iff `swap == 1`, by an xor mask (RFC 7748 §5
    /// cswap).
    fn cswap(swap: u64, st: *State, comptime a: Slot, comptime b: Slot) void {
        const m = 0 -% swap;
        for (&st[@intFromEnum(a)], &st[@intFromEnum(b)]) |*x, *y| {
            const t = m & (x.* ^ y.*);
            x.* ^= t;
            y.* ^= t;
        }
    }

    const clobbers: std.builtin.assembly.Clobbers = .{
        .rax = true,
        .rbx = true,
        .rdx = true,
        .r8 = true,
        .r9 = true,
        .r10 = true,
        .r11 = true,
        .r12 = true,
        .r13 = true,
        .r14 = true,
        .r15 = true,
        .cc = true,
        .memory = true,
    };

    /// The asm bodies below address their operands as `N(%[o])`, `N(%[a])`,
    /// `N(%[b])`; this rewrites each to `N+<slot offset>(%[p])` against the
    /// one state pointer.
    fn rebase(comptime src: []const u8, comptime o: Slot, comptime a: Slot, comptime b: Slot) []const u8 {
        comptime {
            @setEvalBranchQuota(10_000_000);
            var s = src;
            for (.{ .{ "(%[o])", o }, .{ "(%[a])", a }, .{ "(%[b])", b } }) |r| {
                s = replace(s, r[0], std.fmt.comptimePrint("+{d}(%[p])", .{@as(usize, @intFromEnum(r[1])) * @sizeOf(Limbs)}));
            }
            return s;
        }
    }

    fn replace(comptime s: []const u8, comptime needle: []const u8, comptime with: []const u8) []const u8 {
        comptime {
            @setEvalBranchQuota(10_000_000);
            var buf: [std.mem.replacementSize(u8, s, needle, with)]u8 = undefined;
            _ = std.mem.replace(u8, s, needle, with, &buf);
            const final = buf;
            return &final;
        }
    }

    fn Ops(comptime use_adx: bool) type {
        return struct {
            inline fn run(comptime body: []const u8, st: *State, comptime o: Slot, comptime a: Slot, comptime b: Slot) void {
                asm volatile (rebase(body, o, a, b)
                    :
                    : [p] "r" (st),
                    : clobbers);
            }

            /// `o = a · b`. `o` may alias an input on the ADX path, which
            /// writes `o` only after its last read; the MULX-only path parks
            /// finished product words in `o` mid-way, so there it must not.
            inline fn fmul(st: *State, comptime o: Slot, comptime a: Slot, comptime b: Slot) void {
                if (use_adx) {
                    run(mul_adx, st, o, a, b);
                } else {
                    comptime std.debug.assert(o != a and o != b);
                    run(mul_mulx, st, o, a, b);
                }
            }

            /// `o = a²`; `o` may alias `a` (written after the last read).
            inline fn sq(st: *State, comptime o: Slot, comptime a: Slot) void {
                run(sq_mulx, st, o, a, a);
            }

            /// `o = a + b`; `o` may alias either input.
            inline fn add(st: *State, comptime o: Slot, comptime a: Slot, comptime b: Slot) void {
                run(add_asm, st, o, a, b);
            }

            /// `o = a − b`; `o` may alias either input.
            inline fn sub(st: *State, comptime o: Slot, comptime a: Slot, comptime b: Slot) void {
                run(sub_asm, st, o, a, b);
            }

            /// `o = a · 121665` — RFC 7748's `a24 = (486662 − 2) / 4`.
            inline fn mul121665(st: *State, comptime o: Slot, comptime a: Slot) void {
                run(mul121665_asm, st, o, a, a);
            }

            /// `o = a^(2^n)`, `n ≥ 1`.
            inline fn sqN(st: *State, comptime o: Slot, comptime a: Slot, comptime n: usize) void {
                sq(st, o, a);
                for (1..n) |_| sq(st, o, o);
            }

            /// `o = z^(p−2)` by a fixed chain of 254 squarings and 11
            /// multiplications (the count Bernstein gives in "Curve25519: new
            /// Diffie-Hellman speed records", PKC 2006); `0 ↦ 0`, as std's
            /// `invert`. The exponent of each intermediate is in the comments.
            /// Uses slots `t` and `v*`; `o` must be none of them.
            fn invert(st: *State, comptime o: Slot, comptime z: Slot) void {
                sq(st, .v2, z); // 2
                sqN(st, .t, .v2, 2); // 8
                fmul(st, .v9, .t, z); // 9
                fmul(st, .v11, .v9, .v2); // 11
                sq(st, .t, .v11); // 22
                fmul(st, .v5, .t, .v9); // 2^5 − 1
                sqN(st, .t, .v5, 5);
                fmul(st, .v10, .t, .v5); // 2^10 − 1
                sqN(st, .t, .v10, 10);
                fmul(st, .v20, .t, .v10); // 2^20 − 1
                sqN(st, .t, .v20, 20);
                fmul(st, .v40, .t, .v20); // 2^40 − 1
                sqN(st, .t, .v40, 10);
                fmul(st, .v50, .t, .v10); // 2^50 − 1
                sqN(st, .t, .v50, 50);
                fmul(st, .v100, .t, .v50); // 2^100 − 1
                sqN(st, .t, .v100, 100);
                fmul(st, .v200, .t, .v100); // 2^200 − 1
                sqN(st, .t, .v200, 50);
                fmul(st, .v250, .t, .v50); // 2^250 − 1
                sqN(st, .t, .v250, 5); // 2^255 − 2^5
                fmul(st, o, .t, .v11); // 2^255 − 21 = p − 2
            }
        };
    }

    // ── the asm bodies (AT&T syntax: `op src, dst`; `mulx src, lo, hi`) ──
    //
    // All read their operands through `N(%[a])`/`N(%[b])` and write the
    // result through `N(%[o])` — `rebase` turns those into offsets from the
    // one state pointer. Every body reads its inputs completely before its
    // first store to `o` except `mul_mulx`, which parks the three finished
    // low words of the product in `o` to free registers (so `Ops.fmul`
    // asserts `o` distinct from its inputs there).

    /// Fold a 5-word value `r8,r9,r10,r11 + 2^256·<top>` (top < 2^32) into
    /// four words: `+38·top`, then one more `+38` if that carried (a second
    /// carry is impossible: after a wrap the low words are < 38·2^32).
    fn foldTop(comptime top: []const u8, comptime w: [4][]const u8) []const u8 {
        return "imulq $38, " ++ top ++ ", %%rax\n" ++
            "addq %%rax, " ++ w[0] ++ "\n" ++
            "adcq $0, " ++ w[1] ++ "\n" ++
            "adcq $0, " ++ w[2] ++ "\n" ++
            "adcq $0, " ++ w[3] ++ "\n" ++
            "sbbq %%rax, %%rax\n" ++
            "andq $38, %%rax\n" ++
            "addq %%rax, " ++ w[0] ++ "\n" ++
            "movq " ++ w[0] ++ ", 0(%[o])\n" ++
            "movq " ++ w[1] ++ ", 8(%[o])\n" ++
            "movq " ++ w[2] ++ ", 16(%[o])\n" ++
            "movq " ++ w[3] ++ ", 24(%[o])\n";
    }

    /// 512-bit product in r8..r15 (t0..t7) → `t0..t3 + 38·(t4..t7)`, single
    /// carry chain (MULX only). The five-word `38·high` is formed first in
    /// rax,rbx,r12,r13,r15, then added to the low half.
    const reduce_r8_r15 =
        \\movl $38, %%edx
        \\mulxq %%r12, %%rax, %%r12
        \\mulxq %%r13, %%rbx, %%r13
        \\addq %%r12, %%rbx
        \\mulxq %%r14, %%r12, %%r14
        \\adcq %%r13, %%r12
        \\mulxq %%r15, %%r13, %%r15
        \\adcq %%r14, %%r13
        \\adcq $0, %%r15
        \\addq %%rax, %%r8
        \\adcq %%rbx, %%r9
        \\adcq %%r12, %%r10
        \\adcq %%r13, %%r11
        \\adcq $0, %%r15
        \\
    ++ foldTop("%%r15", .{ "%%r8", "%%r9", "%%r10", "%%r11" });

    /// Same reduction with two interleaved carry chains (ADX): CF carries
    /// the low words of `38·t_{4+j}` into t_j, OF the high words into
    /// t_{j+1}; rbx is the zero register.
    const reduce_r8_r15_adx =
        \\movl $38, %%edx
        \\xorl %%ebx, %%ebx
        \\mulxq %%r12, %%rax, %%r12
        \\adcxq %%rax, %%r8
        \\adoxq %%r12, %%r9
        \\mulxq %%r13, %%rax, %%r13
        \\adcxq %%rax, %%r9
        \\adoxq %%r13, %%r10
        \\mulxq %%r14, %%rax, %%r14
        \\adcxq %%rax, %%r10
        \\adoxq %%r14, %%r11
        \\mulxq %%r15, %%rax, %%r15
        \\adcxq %%rax, %%r11
        \\adoxq %%rbx, %%r15
        \\adcxq %%rbx, %%r15
        \\
    ++ foldTop("%%r15", .{ "%%r8", "%%r9", "%%r10", "%%r11" });

    /// Row 0 of a schoolbook product, `a · b0` into r8..r12 (one chain).
    const row0 =
        \\movq 0(%[b]), %%rdx
        \\mulxq 0(%[a]), %%r8, %%r9
        \\mulxq 8(%[a]), %%rax, %%r10
        \\addq %%rax, %%r9
        \\mulxq 16(%[a]), %%rax, %%r11
        \\adcq %%rax, %%r10
        \\mulxq 24(%[a]), %%rax, %%r12
        \\adcq %%rax, %%r11
        \\adcq $0, %%r12
        \\
    ;

    /// Row `i` (1..3) with ADX: `a · b_i` accumulated into t_i..t_{i+4};
    /// `xor` zeroes the fresh top word t_{i+4} and clears CF and OF.
    fn rowAdx(comptime i: u8, comptime t: [5][]const u8) []const u8 {
        const off = std.fmt.comptimePrint("{d}", .{8 * @as(u32, i)});
        var s: []const u8 = "movq " ++ off ++ "(%[b]), %%rdx\n" ++
            "xorl " ++ t[4] ++ "d, " ++ t[4] ++ "d\n";
        for (0..4) |j| {
            const aoff = std.fmt.comptimePrint("{d}", .{8 * j});
            s = s ++ "mulxq " ++ aoff ++ "(%[a]), %%rax, %%rbx\n" ++
                "adcxq %%rax, " ++ t[j] ++ "\n" ++
                "adoxq %%rbx, " ++ t[j + 1] ++ "\n";
        }
        return s ++ "adcq $0, " ++ t[4] ++ "\n";
    }

    const mul_adx = row0 ++
        rowAdx(1, .{ "%%r9", "%%r10", "%%r11", "%%r12", "%%r13" }) ++
        rowAdx(2, .{ "%%r10", "%%r11", "%%r12", "%%r13", "%%r14" }) ++
        rowAdx(3, .{ "%%r11", "%%r12", "%%r13", "%%r14", "%%r15" }) ++
        reduce_r8_r15_adx;

    /// Row `i` (1..3), MULX only: the row product `a · b_i` is formed as five
    /// words in r13,r14,r15,rbx,<top> with one chain, then added into
    /// t_i..t_{i+3},<top> with a second. `top` holds t_{i−1} on entry, which
    /// is final by then: it is parked in `o[i−1]` and the register reused as
    /// the new top word t_{i+4}.
    fn rowMulx(comptime i: u8, comptime t: [4][]const u8, comptime top: []const u8) []const u8 {
        const off = std.fmt.comptimePrint("{d}", .{8 * @as(u32, i)});
        const park = std.fmt.comptimePrint("{d}", .{8 * (@as(u32, i) - 1)});
        return "movq " ++ top ++ ", " ++ park ++ "(%[o])\n" ++
            "movq " ++ off ++ "(%[b]), %%rdx\n" ++
            \\mulxq 0(%[a]), %%r13, %%r14
            \\mulxq 8(%[a]), %%rax, %%r15
            \\addq %%rax, %%r14
            \\mulxq 16(%[a]), %%rax, %%rbx
            \\adcq %%rax, %%r15
            \\
        ++ "mulxq 24(%[a]), %%rax, " ++ top ++ "\n" ++
            "adcq %%rax, %%rbx\n" ++
            "adcq $0, " ++ top ++ "\n" ++
            "addq %%r13, " ++ t[0] ++ "\n" ++
            "adcq %%r14, " ++ t[1] ++ "\n" ++
            "adcq %%r15, " ++ t[2] ++ "\n" ++
            "adcq %%rbx, " ++ t[3] ++ "\n" ++
            "adcq $0, " ++ top ++ "\n";
    }

    // Register walk (t_k = product word k): after row 0 t0..t4 = r8..r12;
    // row 1 parks t0 and reuses r8 as t5; row 2 parks t1, r9 = t6; row 3
    // parks t2, r10 = t7. Product: o[0..3) = t0..t2, r11 = t3, and
    // t4..t7 = r12, r8, r9, r10.
    const mul_mulx = row0 ++
        rowMulx(1, .{ "%%r9", "%%r10", "%%r11", "%%r12" }, "%%r8") ++
        rowMulx(2, .{ "%%r10", "%%r11", "%%r12", "%%r8" }, "%%r9") ++
        rowMulx(3, .{ "%%r11", "%%r12", "%%r8", "%%r9" }, "%%r10") ++
        // 38·(t4..t7) as five words r13,r14,r15,rbx,r12, then + (t0..t3).
        \\movl $38, %%edx
        \\mulxq %%r12, %%r13, %%r14
        \\mulxq %%r8, %%rax, %%r15
        \\addq %%rax, %%r14
        \\mulxq %%r9, %%rax, %%rbx
        \\adcq %%rax, %%r15
        \\mulxq %%r10, %%rax, %%r12
        \\adcq %%rax, %%rbx
        \\adcq $0, %%r12
        \\addq 0(%[o]), %%r13
        \\adcq 8(%[o]), %%r14
        \\adcq 16(%[o]), %%r15
        \\adcq %%r11, %%rbx
        \\adcq $0, %%r12
        \\
    ++ foldTop("%%r12", .{ "%%r13", "%%r14", "%%r15", "%%rbx" });

    /// Squaring: the six cross products a_i·a_j (i < j) into t1..t6, doubled
    /// by an add chain into t1..t7, plus the four squares a_i² on the
    /// diagonal — 10 `mulx`. One chain at a time, so MULX only.
    const sq_mulx =
        // a0·(a1, a2, a3) → t1..t4 = r9..r12
        \\movq 0(%[a]), %%rdx
        \\mulxq 8(%[a]), %%r9, %%r10
        \\mulxq 16(%[a]), %%rax, %%r11
        \\addq %%rax, %%r10
        \\mulxq 24(%[a]), %%rax, %%r12
        \\adcq %%rax, %%r11
        \\adcq $0, %%r12
        // a1·(a2, a3): three words (rax, r15, r13) at t3..t5
        \\movq 8(%[a]), %%rdx
        \\mulxq 16(%[a]), %%rax, %%rbx
        \\mulxq 24(%[a]), %%r15, %%r13
        \\addq %%rbx, %%r15
        \\adcq $0, %%r13
        \\addq %%rax, %%r11
        \\adcq %%r15, %%r12
        \\adcq $0, %%r13
        // a2·a3 → t5, t6 = r13, r14
        \\movq 16(%[a]), %%rdx
        \\mulxq 24(%[a]), %%rax, %%r14
        \\addq %%rax, %%r13
        \\adcq $0, %%r14
        // ×2 into t1..t7 (r15 = t7 = the bit shifted out)
        \\xorl %%r15d, %%r15d
        \\addq %%r9, %%r9
        \\adcq %%r10, %%r10
        \\adcq %%r11, %%r11
        \\adcq %%r12, %%r12
        \\adcq %%r13, %%r13
        \\adcq %%r14, %%r14
        \\adcq $0, %%r15
        // + a0², a1², a2², a3² on the diagonal (t0 = r8); `mov` and `mulx`
        // leave CF alone, so this is one chain
        \\movq 0(%[a]), %%rdx
        \\mulxq %%rdx, %%r8, %%rax
        \\addq %%rax, %%r9
        \\movq 8(%[a]), %%rdx
        \\mulxq %%rdx, %%rax, %%rbx
        \\adcq %%rax, %%r10
        \\adcq %%rbx, %%r11
        \\movq 16(%[a]), %%rdx
        \\mulxq %%rdx, %%rax, %%rbx
        \\adcq %%rax, %%r12
        \\adcq %%rbx, %%r13
        \\movq 24(%[a]), %%rdx
        \\mulxq %%rdx, %%rax, %%rbx
        \\adcq %%rax, %%r14
        \\adcq %%rbx, %%r15
        \\
    ++ reduce_r8_r15;

    /// `a + b`: a 257-bit sum, the carry folded as +38, and a second +38 if
    /// that fold carried (then the low words are < 38, so no third).
    const add_asm =
        \\movq 0(%[a]), %%r8
        \\movq 8(%[a]), %%r9
        \\movq 16(%[a]), %%r10
        \\movq 24(%[a]), %%r11
        \\addq 0(%[b]), %%r8
        \\adcq 8(%[b]), %%r9
        \\adcq 16(%[b]), %%r10
        \\adcq 24(%[b]), %%r11
        \\sbbq %%rax, %%rax
        \\andq $38, %%rax
        \\addq %%rax, %%r8
        \\adcq $0, %%r9
        \\adcq $0, %%r10
        \\adcq $0, %%r11
        \\sbbq %%rax, %%rax
        \\andq $38, %%rax
        \\addq %%rax, %%r8
        \\movq %%r8, 0(%[o])
        \\movq %%r9, 8(%[o])
        \\movq %%r10, 16(%[o])
        \\movq %%r11, 24(%[o])
    ;

    /// `a − b`: a borrow means `+2^256 ≡ +38` was added, so 38 is taken off;
    /// if that borrows again the value was < 38 and one more −38 cannot.
    const sub_asm =
        \\movq 0(%[a]), %%r8
        \\movq 8(%[a]), %%r9
        \\movq 16(%[a]), %%r10
        \\movq 24(%[a]), %%r11
        \\subq 0(%[b]), %%r8
        \\sbbq 8(%[b]), %%r9
        \\sbbq 16(%[b]), %%r10
        \\sbbq 24(%[b]), %%r11
        \\sbbq %%rax, %%rax
        \\andq $38, %%rax
        \\subq %%rax, %%r8
        \\sbbq $0, %%r9
        \\sbbq $0, %%r10
        \\sbbq $0, %%r11
        \\sbbq %%rax, %%rax
        \\andq $38, %%rax
        \\subq %%rax, %%r8
        \\movq %%r8, 0(%[o])
        \\movq %%r9, 8(%[o])
        \\movq %%r10, 16(%[o])
        \\movq %%r11, 24(%[o])
    ;

    /// `a · 121665`: a five-word product (top < 2^17), folded.
    const mul121665_asm =
        \\movl $121665, %%edx
        \\mulxq 0(%[a]), %%r8, %%r9
        \\mulxq 8(%[a]), %%rax, %%r10
        \\addq %%rax, %%r9
        \\mulxq 16(%[a]), %%rax, %%r11
        \\adcq %%rax, %%r10
        \\mulxq 24(%[a]), %%rax, %%r12
        \\adcq %%rax, %%r11
        \\adcq $0, %%r12
        \\
    ++ foldTop("%%r12", .{ "%%r8", "%%r9", "%%r10", "%%r11" });
};

/// `s * B` over Ristretto255 against the ristretto255 base point — the
/// fixed-base comb of `mulBase` (ristretto255's base point IS Edwards25519's,
/// `Ristretto255.basePoint.p`; pinned by a test below).
pub fn mulRistrettoBase(s: [32]u8) Ristretto255 {
    var sc = s;
    defer std.crypto.secureZero(u8, &sc);
    return .{ .p = combMulBase(&sc) };
}

// ── constant-time multi-scalar multiplication (audit `bulletproofs` B9) ───
//
// `Σ s_i·P_i` for SECRET scalars over caller-validated points, by Straus's
// interleaving (E. G. Straus, "Addition chains of vectors", Amer. Math.
// Monthly 71, 1964) with the same fixed 4-bit window and the same `pcSelect`
// as `mul`: every term gets its own 16-entry table, and all terms SHARE one
// chain of doublings — per window, one `pcSelect`+add per term, then four
// doublings for the whole group. That is the constant-time counterpart of
// the bucket (Pippenger) method, which is not: bucket membership depends on
// the scalar digits. It is the shape dalek's `MultiscalarMul` documents as
// constant-time, implemented here from the description.
//
// Cost per term drops from 64 adds + 252 doublings + a 14-operation table to
// 64 adds + 252/k doublings + the table, for chunks of k terms.
//
// Chunking: tables for `msm_chunk` terms live on the stack at once
// (8 × 16 points ≈ 21.5 KiB), so the function needs no allocator; a longer
// input is summed chunk by chunk. The chunk count and every loop bound depend
// on `scalars.len` only — public. Nothing branches on a scalar or on a digit.

/// Terms whose tables are held at once; a stack-size bound, not a tuning knob
/// the result depends on (any value gives the same point).
const msm_chunk = 8;

/// `Σ scalars[i]·points[i]` over Ristretto255, **constant-time in every
/// scalar** and total — the neutral element is a value. Each scalar is used
/// as-is, all 256 bits, exactly as `mulRistretto` uses it, and the result is
/// the same group element as the sum of the `mulRistretto` products.
/// Points are not validated (module doc comment). `scalars.len` must equal
/// `points.len`; a mismatch is a caller bug and panics — the lengths are
/// public, but an error union here would be the shape this module refuses.
pub fn mulMultiRistretto(scalars: []const [32]u8, points: []const Ristretto255) Ristretto255 {
    if (scalars.len != points.len) @panic("ct25519.mulMultiRistretto: scalars.len != points.len");
    var total = Edwards25519.identityElement;
    var start: usize = 0;
    while (start < scalars.len) {
        const k = @min(msm_chunk, scalars.len - start);
        total = total.add(strausChunk(scalars[start..][0..k], points[start..][0..k]));
        start += k;
    }
    return .{ .p = total };
}

/// One Straus pass over at most `msm_chunk` terms.
fn strausChunk(scalars: []const [32]u8, points: []const Ristretto255) Edwards25519 {
    var tabs: [msm_chunk][16]Edwards25519 = undefined;
    for (tabs[0..points.len], points) |*t, p| {
        t.* = if (p.p.is_base) base_pc else precompute(p.p); // branch on a PUBLIC flag
    }
    var q = Edwards25519.identityElement;
    var pos: usize = 252;
    while (true) : (pos -= 4) {
        for (tabs[0..scalars.len], scalars) |*t, *s| {
            const slot: u4 = @truncate(s[pos >> 3] >> @as(u3, @truncate(pos)));
            q = q.add(pcSelect(t, slot));
        }
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    return q;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const scalar = Edwards25519.scalar;

test {
    // Opt-in micro-benchmark (audit C9); skips unless CT25519_BENCH is set.
    _ = @import("bench.zig");
}

/// Deterministic scalars — this module has no RNG and its tests must be
/// reproducible, so the "random" scalars are a SHA-512 stream reduced mod L.
fn nthScalar(n: u32) [32]u8 {
    var seed: [4]u8 = undefined;
    std.mem.writeInt(u32, &seed, n, .little);
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&seed, &wide, .{});
    return scalar.reduce64(wide);
}

test "mul: bit-exact against std's Edwards25519.mul on the base point" {
    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        const s = nthScalar(i);
        const want = try Edwards25519.basePoint.mul(s);
        try testing.expectEqualSlices(u8, &want.toBytes(), &mulBase(s).toBytes());
    }
}

test "mul: bit-exact against std's Edwards25519.mul on non-base points" {
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const p = try Edwards25519.basePoint.mul(nthScalar(i +% 1_000));
        const s = nthScalar(i +% 2_000);
        const want = try p.mul(s);
        try testing.expectEqualSlices(u8, &want.toBytes(), &mul(p, s).toBytes());
    }
}

test "mulRistretto: bit-exact against std's Ristretto255.mul" {
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const p = try Ristretto255.basePoint.mul(nthScalar(i +% 3_000));
        const s = nthScalar(i +% 4_000);
        const want = try p.mul(s);
        try testing.expect(mulRistretto(p, s).equivalent(want));
        try testing.expectEqualSlices(u8, &want.toBytes(), &mulRistretto(p, s).toBytes());
    }
}

test "mul: the neutral element is a VALUE, where std raises an error" {
    // This is the entire reason the module exists. std refuses both of
    // these; the whole point is that we do not, because refusing means
    // branching on a secret-derived value.
    const zero = [_]u8{0} ** 32;
    try testing.expectError(error.IdentityElement, Edwards25519.basePoint.mul(zero));
    try testing.expectError(error.IdentityElement, Ristretto255.basePoint.mul(zero));

    const id_bytes = Edwards25519.identityElement.toBytes();
    try testing.expectEqualSlices(u8, &id_bytes, &mulBase(zero).toBytes());
    // The ristretto255 identity encodes as 32 zero bytes (RFC 9496 §4.3.2).
    try testing.expectEqualSlices(u8, &zero, &mulRistrettoBase(zero).toBytes());

    // `s = L` (the group order) is the other scalar that lands on the
    // neutral element without being all-zero bytes — the case a "reject an
    // all-zero scalar up front" guard would miss.
    var order: [32]u8 = undefined;
    std.mem.writeInt(u256, &order, scalar.field_order, .little);
    try testing.expectError(error.IdentityElement, Edwards25519.basePoint.mul(order));
    try testing.expectEqualSlices(u8, &id_bytes, &mulBase(order).toBytes());
    try testing.expectEqualSlices(u8, &zero, &mulRistrettoBase(order).toBytes());
}

test "mul: carries no error set, so no call site can branch on the scalar" {
    // The contagious half of the finding: std's `mul` returns an error
    // union, which forces every caller to branch a second time. Pin that
    // these do not, for all four entry points.
    inline for (.{ mul, mulBase, mulRistretto, mulRistrettoBase }) |f| {
        const ret = @typeInfo(@TypeOf(f)).@"fn".return_type.?;
        try testing.expect(@typeInfo(ret) != .error_union);
    }
    // ...and that std really is the shape we are describing.
    const std_ret = @typeInfo(@TypeOf(Edwards25519.mul)).@"fn".return_type.?;
    try testing.expect(@typeInfo(std_ret) == .error_union);
}

test "mulBase: re-derives RFC 8032 §7.1's published Ed25519 public keys" {
    // External anchor: the Ed25519 public key of RFC 8032 §7.1's TEST 1 and
    // TEST 2 is `[clamp(SHA-512(sk)[0..32])]B` encoded — a value published
    // by the RFC, not by us and not by std. A typo in either constant makes
    // this test red immediately.
    const Vector = struct { sk: *const [64]u8, pk: *const [64]u8 };
    const vectors = [_]Vector{
        .{
            .sk = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            .pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        },
        .{
            .sk = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            .pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        },
    };
    for (vectors) |v| {
        var sk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sk, v.sk);
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, v.pk);

        var h: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(&sk, &h, .{});
        var a: [32]u8 = h[0..32].*;
        scalar.clamp(&a);
        try testing.expectEqualSlices(u8, &want, &mulBase(a).toBytes());
    }
}

test "mul: reads ALL 256 scalar bits (no silent truncation of the top window)" {
    // Every other test in this file feeds a scalar that is either reduced
    // mod `L` (`nthScalar` ⇒ < 2^253) or clamped (RFC 8032 ⇒ bit 255 forced
    // to 0), so bit 255 is set in NONE of them. Masking it off inside `mul`
    // therefore used to leave the suite green — the audit's `I2` injection.
    // Oracles here are BOTH std's `mul` and a doubling chain, so this pins
    // the value and not merely std's agreement with us.
    var bit: u16 = 250;
    while (bit < 256) : (bit += 1) {
        var s = [_]u8{0} ** 32;
        s[bit >> 3] = @as(u8, 1) << @as(u3, @truncate(bit));
        const ours = mulBase(s).toBytes();
        const want = try Edwards25519.basePoint.mul(s);
        try testing.expectEqualSlices(u8, &want.toBytes(), &ours);
        var chain = Edwards25519.basePoint;
        var i: u16 = 0;
        while (i < bit) : (i += 1) chain = chain.dbl();
        try testing.expectEqualSlices(u8, &chain.toBytes(), &ours);
    }
    // 2^256 - 1: an unreduced scalar far above `L`, to pin that nothing
    // silently reduces or rejects it.
    const ones = [_]u8{0xff} ** 32;
    const want_ones = try Edwards25519.basePoint.mul(ones);
    try testing.expectEqualSlices(u8, &want_ones.toBytes(), &mulBase(ones).toBytes());
}

test "mul: degenerate INPUT points, where std refuses to answer at all" {
    // This module deliberately drops std's `WeakPublicKey` check on the
    // point (see the module doc comment), so it answers on inputs std
    // rejects — and those answers were previously untested. The oracle is
    // repeated addition: independent of std's ladder AND of this one.
    const s = nthScalar(9_001);
    try testing.expectEqualSlices(
        u8,
        &Edwards25519.identityElement.toBytes(),
        &mul(Edwards25519.identityElement, s).toBytes(),
    );

    // A point of order exactly 8 (asserted below) — the RFC 8032 §5.1.7
    // "small order" shape. std's `mul` refuses it outright.
    const torsion_bytes = [_]u8{
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
        0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
        0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    };
    const t8 = try Edwards25519.fromBytes(torsion_bytes);
    try testing.expectError(error.WeakPublicKey, t8.mul(s));
    try testing.expectError(error.WeakPublicKey, t8.rejectLowOrder());

    const id_bytes = Edwards25519.identityElement.toBytes();
    var acc = Edwards25519.identityElement; // acc == k*t8
    var k: u8 = 0;
    while (k < 10) : (k += 1) {
        var sk = [_]u8{0} ** 32;
        sk[0] = k;
        try testing.expectEqualSlices(u8, &acc.toBytes(), &mul(t8, sk).toBytes());
        // order exactly 8: identity at k = 0 and k = 8, nowhere between.
        const is_id = std.mem.eql(u8, &acc.toBytes(), &id_bytes);
        try testing.expectEqual(k % 8 == 0, is_id);
        acc = acc.add(t8);
    }
}

test "mulBase/mulRistrettoBase take the comptime base table, and both table paths agree" {
    // The comptime table is reached only while std still marks its own base
    // points `is_base` — a std internal this module cannot enforce. If a std
    // upgrade ever built `Ristretto255.basePoint` from bytes instead, every
    // `mulRistrettoBase` call would quietly start doing an online 15-entry
    // precomputation and no other test would notice. Pin the precondition.
    try testing.expect(Edwards25519.basePoint.is_base);
    try testing.expect(Ristretto255.basePoint.p.is_base);

    // ...and the comptime-folded table must agree with the online one, so a
    // future divergence is a red test rather than only a slowdown.
    const b = try Edwards25519.fromBytes(Edwards25519.basePoint.toBytes());
    try testing.expect(!b.is_base);
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const s = nthScalar(i +% 7_000);
        try testing.expectEqualSlices(u8, &mulBase(s).toBytes(), &mul(b, s).toBytes());
    }
}

// ── C3 comb: P5 evidence 1 + 2 (bit-exact KAT set and randomized
// differential against the pre-C3 algorithm). The reference is
// `mul(Edwards25519.basePoint, s)` / `mulRistretto(Ristretto255.basePoint, s)`:
// that is, byte for byte, the ladder `mulBase`/`mulRistrettoBase` ran before
// C3 (`git show 74645800:modules/ct25519/src/root.zig`), and it stays in the
// module exactly so this comparison never loses its oracle. Every comparison
// is on the canonical 32-byte encoding.

fn expectCombMatchesLadder(s: [32]u8) !void {
    try testing.expectEqualSlices(
        u8,
        &mul(Edwards25519.basePoint, s).toBytes(),
        &mulBase(s).toBytes(),
    );
    try testing.expectEqualSlices(
        u8,
        &mulRistretto(Ristretto255.basePoint, s).toBytes(),
        &mulRistrettoBase(s).toBytes(),
    );
}

test "C3 comb: every nibble value at every position vs the ladder (all 256 table entries, both signs, every carry)" {
    // `v·16^pos` for pos 0..63, v 0..15. v in 1..7 selects `+tab[pos/2][v-1]`;
    // v in 8..15 recodes to `-(16-v)` (magnitudes 8..1, the negative half)
    // with a carry into pos+1 — or, at pos 63, into `comb_carry`. Odd `pos`
    // go through the doubling pass, even ones do not. So this set reaches
    // every entry of `comb_table` with both signs and the carry point.
    var n: usize = 0;
    for (0..64) |pos| {
        for (0..16) |v| {
            var s = [_]u8{0} ** 32;
            s[pos >> 1] = @as(u8, @intCast(v)) << @as(u3, @intCast(4 * (pos & 1)));
            try expectCombMatchesLadder(s);
            n += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1024), n);
}

test "C3 comb: carry-chain and boundary scalars vs the ladder" {
    var order: [32]u8 = undefined;
    std.mem.writeInt(u256, &order, scalar.field_order, .little);
    const L: u256 = scalar.field_order;
    const ints = [_]u256{
        0, 1, 2, 7, 8, 9, 15, 16, 17,
        L - 1,          L,              L + 1,    2 * L,          ~L +% 1, // 2^256 - L
        1 << 252,       (1 << 252) - 1, 1 << 253, (1 << 255) - 1, 1 << 255,
        (1 << 255) + 1,
        ~@as(u256, 0), // 2^256 - 1: all 64 digits carry
        ~@as(u256, 0) - 1,
        0x8888888888888888888888888888888888888888888888888888888888888888, // every digit -8, carry ripples through all 64
        0x7777777777777777777777777777777777777777777777777777777777777777, // every digit +7, no carry
        0x7878787878787878787878787878787878787878787878787878787878787878,
        0x8787878787878787878787878787878787878787878787878787878787878787,
        0xf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0,
        0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f,
        0x8000000000000000000000000000000000000000000000000000000000000000,
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        0x0000000000000000000000000000000000000000000000000000000000000008,
        0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffffff00000000000000000000000000000000,
    };
    for (ints) |x| {
        var s: [32]u8 = undefined;
        std.mem.writeInt(u256, &s, x, .little);
        try expectCombMatchesLadder(s);
    }
    try testing.expectEqualSlices(u8, &order, &blk: {
        var s: [32]u8 = undefined;
        std.mem.writeInt(u256, &s, ints[10], .little);
        break :blk s;
    });
}

test "C3 comb: randomized differential vs the ladder (full 256-bit and reduced scalars)" {
    // Debug is ~50x slower per multiply; the ReleaseFast lane carries the volume.
    const count: usize = if (@import("builtin").mode == .Debug) 200 else 20_000;
    var prng = std.Random.DefaultPrng.init(0xC3_C0_4B_25_51_9E);
    const random = prng.random();
    for (0..count) |i| {
        var s: [32]u8 = undefined;
        random.bytes(&s); // unreduced, all 256 bits live
        if (i % 2 == 1) s = scalar.reduce(s);
        try expectCombMatchesLadder(s);
    }
}

test "C3 comb: the recoding reconstructs every 256-bit scalar, digits in [-8, 7]" {
    // Isolates `combRecode` from the table: a recoding fault that happens to
    // cancel in the point arithmetic still shows up here as an integer.
    var prng = std.Random.DefaultPrng.init(0x5EC0DE);
    const random = prng.random();
    const fixed = [_]u256{ 0, ~@as(u256, 0), 0x8888888888888888888888888888888888888888888888888888888888888888 };
    for (0..2000 + fixed.len) |i| {
        var s: [32]u8 = undefined;
        if (i < fixed.len) std.mem.writeInt(u256, &s, fixed[i], .little) else random.bytes(&s);
        var e: [64]i8 = undefined;
        const carry = combRecode(&s, &e);
        try testing.expect(carry <= 1);
        var acc: i512 = @as(i512, carry) << 256;
        var k: usize = 64;
        while (k > 0) {
            k -= 1;
            try testing.expect(e[k] >= -8 and e[k] <= 7);
            acc += @as(i512, e[k]) << @as(u9, @intCast(4 * k));
        }
        try testing.expectEqual(@as(i512, std.mem.readInt(u256, &s, .little)), acc);
    }
}

test "C3 comb: the table holds (k+1)·16^(2j)·B and the carry point is 2^256·B" {
    // Independent of the comb's evaluation order: each entry against the
    // ladder on the scalar it claims to be. 2^256·B has no 32-byte scalar, so
    // it is checked as 16·(2^252·B), i.e. four doublings of a ladder result.
    for (0..comb_rows) |j| {
        for (0..comb_teeth) |k| {
            var s = [_]u8{0} ** 32;
            s[j] = @intCast(k + 1); // byte j = 16^(2j)
            try testing.expectEqualSlices(u8, &mul(Edwards25519.basePoint, s).toBytes(), &comb_table[j][k].toBytes());
        }
    }
    var s252 = [_]u8{0} ** 32;
    s252[31] = 0x10;
    const want = mul(Edwards25519.basePoint, s252).dbl().dbl().dbl().dbl();
    try testing.expectEqualSlices(u8, &want.toBytes(), &comb_carry.toBytes());
    // ristretto255's base point is Edwards25519's, which `mulRistrettoBase`
    // relies on when it calls the Edwards comb.
    try testing.expectEqualSlices(u8, &Edwards25519.basePoint.toBytes(), &Ristretto255.basePoint.p.toBytes());
}

// ── B9 MSM: P5 evidence 1 + 2 against the loop it replaces ───────────────
// The reference is the sum of `mulRistretto` products — exactly what
// `bulletproofs`' `multiScalarMul` computed before B9, one ladder per term.

fn naiveMulMulti(scalars: []const [32]u8, points: []const Ristretto255) Ristretto255 {
    var acc = Edwards25519.identityElement;
    for (scalars, points) |s, p| acc = acc.add(mulRistretto(p, s).p);
    return .{ .p = acc };
}

fn edgeScalar(i: usize) [32]u8 {
    var s: [32]u8 = undefined;
    const L: u256 = scalar.field_order;
    const v: u256 = switch (i % 6) {
        0 => 0,
        1 => 1,
        2 => L - 1,
        3 => L,
        4 => ~@as(u256, 0),
        else => 0x8888888888888888888888888888888888888888888888888888888888888888,
    };
    std.mem.writeInt(u256, &s, v, .little);
    return s;
}

test "B9 mulMultiRistretto: bit-exact vs the per-term ladder sum across every chunk boundary" {
    const debug = @import("builtin").mode == .Debug;
    const sizes = [_]usize{ 0, 1, 2, 7, 8, 9, 15, 16, 17, 24, 33, 64 };
    const trials: usize = if (debug) 2 else 40;
    var prng = std.Random.DefaultPrng.init(0xB9_5_7A_05);
    const random = prng.random();
    var scalars: [64][32]u8 = undefined;
    var points: [64]Ristretto255 = undefined;
    var compared: usize = 0;
    for (sizes) |n| {
        if (debug and n > 17) continue;
        for (0..trials) |trial| {
            for (0..n) |i| {
                // mix raw 256-bit, reduced and edge scalars
                random.bytes(&scalars[i]);
                if ((i + trial) % 3 == 1) scalars[i] = scalar.reduce(scalars[i]);
                if ((i + trial) % 5 == 2) scalars[i] = edgeScalar(i + trial);
                // mix random multiples, the flagged base point, a decoded (unflagged)
                // base point and the identity
                points[i] = switch ((i + 2 * trial) % 7) {
                    0 => Ristretto255.basePoint,
                    1 => .{ .p = Edwards25519.identityElement },
                    2 => try Ristretto255.fromBytes(Ristretto255.basePoint.toBytes()),
                    else => blk: {
                        var k: [64]u8 = undefined;
                        random.bytes(&k);
                        break :blk .{ .p = mulBase(scalar.reduce64(k)) };
                    },
                };
            }
            const want = naiveMulMulti(scalars[0..n], points[0..n]);
            const got = mulMultiRistretto(scalars[0..n], points[0..n]);
            try testing.expectEqualSlices(u8, &want.toBytes(), &got.toBytes());
            compared += 1;
        }
    }
    try testing.expect(compared >= if (debug) 18 else 480);
}

test "B9 mulMultiRistretto: one term equals mulRistretto; zero terms are the identity; no error set" {
    const zero = [_]u8{0} ** 32;
    try testing.expectEqualSlices(u8, &zero, &mulMultiRistretto(&.{}, &.{}).toBytes());
    const p = try Ristretto255.fromBytes(Ristretto255.basePoint.toBytes());
    for (0..6) |i| {
        const s = edgeScalar(i);
        try testing.expectEqualSlices(u8, &mulRistretto(p, s).toBytes(), &mulMultiRistretto(&.{s}, &.{p}).toBytes());
    }
    const ret = @typeInfo(@TypeOf(mulMultiRistretto)).@"fn".return_type.?;
    try testing.expect(@typeInfo(ret) != .error_union);
}

test "mul: is additively homomorphic in the scalar (fold-boundary sanity)" {
    // Independent of std: `(a+b)*P == a*P + b*P` exercises the window
    // carry/fold seams that a differential over reduced scalars can miss.
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        const a = nthScalar(i +% 5_000);
        const b = nthScalar(i +% 6_000);
        const sum = scalar.add(a, b);
        const lhs = mulBase(sum);
        const rhs = mulBase(a).add(mulBase(b));
        try testing.expectEqualSlices(u8, &lhs.toBytes(), &rhs.toBytes());
    }
}

// ── X25519 on the comb ───────────────────────────────────────────────────

test "X25519: RFC 7748 §6.1's published key pairs and shared secret" {
    const alice_sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const alice_pk = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const bob_sk = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const bob_pk = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    const alice = try X25519.KeyPair.generateDeterministic(alice_sk);
    const bob = try X25519.KeyPair.generateDeterministic(bob_sk);
    try testing.expectEqualSlices(u8, &alice_pk, &alice.public_key);
    try testing.expectEqualSlices(u8, &bob_pk, &bob.public_key);
    try testing.expectEqualSlices(u8, &alice_sk, &alice.secret_key);
    try testing.expectEqualSlices(u8, &shared, &(try X25519.scalarmult(alice.secret_key, bob.public_key)));
    try testing.expectEqualSlices(u8, &shared, &(try X25519.scalarmult(bob.secret_key, alice.public_key)));
}

test "X25519: recoverPublicKey is bit-exact with std over random and edge seeds" {
    // Raw 32-byte seeds, NOT reduced: X25519 clamps, so every bit pattern is a
    // legal secret and the top bits are exercised (bit 255 cleared, 254 set).
    var seed: [32]u8 = undefined;
    var n: u32 = 0;
    while (n < 512) : (n += 1) {
        var wide: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(std.mem.asBytes(&n), &wide, .{});
        seed = wide[0..32].*;
        try testing.expectEqualSlices(u8, &(try std.crypto.dh.X25519.recoverPublicKey(seed)), &(try X25519.recoverPublicKey(seed)));
    }
    for ([_][32]u8{ @splat(0), @splat(0xff), [_]u8{1} ++ [_]u8{0} ** 31, [_]u8{0} ** 31 ++ [_]u8{0x80}, [_]u8{7} ++ [_]u8{0} ** 30 ++ [_]u8{0x40} }) |s| {
        try testing.expectEqualSlices(u8, &(try std.crypto.dh.X25519.recoverPublicKey(s)), &(try X25519.recoverPublicKey(s)));
    }
}

test "X25519: a key pair from the comb agrees with a std key pair on the shared secret" {
    const seed_a: [32]u8 = @splat(0x42);
    const seed_b: [32]u8 = @splat(0x24);
    const ours = try X25519.KeyPair.generateDeterministic(seed_a);
    const theirs = try std.crypto.dh.X25519.KeyPair.generateDeterministic(seed_b);
    const k1 = try X25519.scalarmult(ours.secret_key, theirs.public_key);
    const k2 = try std.crypto.dh.X25519.scalarmult(theirs.secret_key, ours.public_key);
    try testing.expectEqualSlices(u8, &k1, &k2);
    try testing.expectEqual(X25519.KeyPair, @TypeOf(X25519.KeyPair.generate(testing.io)));
}

fn hex32(comptime h: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

// ── X25519 shared secret on the 4×64 field (P6) ──────────────────────────

const all_x25519_backends = [_]X25519Backend{ .stdlib, .mulx, .mulx_adx };

/// Every backend compiled into this build, forced in turn. `.stdlib` is
/// always there; the asm ones exist on an x86-64 LLVM build whose target
/// has BMI2 (and ADX) — the native build on any x86-64 CI runner or laptop.
fn x25519BackendCount() usize {
    var n: usize = 0;
    for (all_x25519_backends) |b| n += @intFromBool(test_hooks.available(b));
    return n;
}

test "P6 X25519: the dispatch follows the target's CPU features" {
    const want: X25519Backend = if (fe64.adx) .mulx_adx else if (fe64.bmi2) .mulx else .stdlib;
    try testing.expectEqual(want, test_hooks.default);
    if (builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm) {
        const f = builtin.cpu.features;
        try testing.expectEqual(std.Target.x86.featureSetHas(f, .bmi2), test_hooks.available(.mulx));
        try testing.expectEqual(std.Target.x86.featureSetHas(f, .bmi2) and std.Target.x86.featureSetHas(f, .adx), test_hooks.available(.mulx_adx));
    }
}

test "P6 X25519: RFC 7748 §5.2 vectors and the 1 / 1,000 iteration chains, every backend" {
    defer test_hooks.forced = null;
    const V = struct { k: [32]u8, u: [32]u8, out: [32]u8 };
    const vectors = [_]V{
        .{
            .k = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            .u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            .out = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        },
        .{
            .k = hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            // top bit of u set: RFC 7748 §5 masks it
            .u = hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            .out = hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        },
    };
    const one = hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    const thousand = hex32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    for (all_x25519_backends) |b| {
        if (!test_hooks.available(b)) continue;
        test_hooks.forced = b;
        for (vectors) |v| try testing.expectEqualSlices(u8, &v.out, &(try X25519.scalarmult(v.k, v.u)));
        var k: [32]u8 = [_]u8{9} ++ [_]u8{0} ** 31;
        var u = k;
        for (1..1001) |i| {
            const out = try X25519.scalarmult(k, u);
            u = k;
            k = out;
            if (i == 1) try testing.expectEqualSlices(u8, &one, &k);
        }
        testing.expectEqualSlices(u8, &thousand, &k) catch |e| {
            std.debug.print("backend {t}\n", .{b});
            return e;
        };
    }
}

test "P6 X25519: RFC 7748 §5.2 1,000,000 iterations (opt-in: CT25519_RFC7748_MILLION)" {
    if (std.testing.environ.getPosix("CT25519_RFC7748_MILLION") == null) return error.SkipZigTest;
    // Only the build's own backend: ~35-50 s per backend at ReleaseFast.
    const million = hex32("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
    var k: [32]u8 = [_]u8{9} ++ [_]u8{0} ** 31;
    var u = k;
    for (0..1_000_000) |_| {
        const out = try X25519.scalarmult(k, u);
        u = k;
        k = out;
    }
    try testing.expectEqualSlices(u8, &million, &k);
}

test "P6 X25519: RFC 7748 §6.1 Diffie-Hellman, every backend" {
    defer test_hooks.forced = null;
    const alice_sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const alice_pk = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const bob_sk = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const bob_pk = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    const nine = [_]u8{9} ++ [_]u8{0} ** 31;
    for (all_x25519_backends) |b| {
        if (!test_hooks.available(b)) continue;
        test_hooks.forced = b;
        // the public keys through the LADDER over u = 9, not the comb
        try testing.expectEqualSlices(u8, &alice_pk, &(try X25519.scalarmult(alice_sk, nine)));
        try testing.expectEqualSlices(u8, &bob_pk, &(try X25519.scalarmult(bob_sk, nine)));
        try testing.expectEqualSlices(u8, &shared, &(try X25519.scalarmult(alice_sk, bob_pk)));
        try testing.expectEqualSlices(u8, &shared, &(try X25519.scalarmult(bob_sk, alice_pk)));
    }
}

/// `std.crypto.dh.X25519.scalarmult` and the forced backend agree on the
/// value AND on `error.IdentityElement`.
fn expectScalarmultMatchesStd(b: X25519Backend, k: [32]u8, u: [32]u8) !void {
    const want = std.crypto.dh.X25519.scalarmult(k, u);
    test_hooks.forced = b;
    const got = X25519.scalarmult(k, u);
    if (want) |w| {
        if (got) |g| {
            if (std.mem.eql(u8, &w, &g)) return;
        } else |_| {}
    } else |we| {
        if (got) |_| {} else |ge| if (we == ge) return;
    }
    std.debug.print("backend {t}\n  k={x}\n  u={x}\n  std={any}\n  got={any}\n", .{ b, k, u, want, got });
    return error.TestExpectedEqual;
}

/// Montgomery u of an Edwards25519 point, `(Z + Y)/(Z − Y)` — identity ↦ 0
/// (std's `invert(0) = 0`), so small-order Edwards points give small-order u.
fn montgomeryU(p: Edwards25519) [32]u8 {
    return p.z.add(p.y).mul(p.z.sub(p.y).invert()).toBytes();
}

/// u-coordinate edge cases: the canonical and non-canonical small values,
/// p−1, p, p+1, 2^255−1, every low-order point of the curve (from an
/// order-8 Edwards point), and their non-canonical `+p` twins where < 2^255.
fn edgeUs(buf: *[40][32]u8) []const [32]u8 {
    var n: usize = 0;
    const p: u256 = (1 << 255) - 19;
    const ints = [_]u256{ 0, 1, 2, 9, 19, p - 1, p, p + 1, p + 9, p + 18, (1 << 255) - 1, (1 << 256) - 1, (1 << 255), (1 << 64) - 1, 1 << 64, (1 << 128) - 1, (1 << 192) - 1 };
    for (ints) |x| {
        std.mem.writeInt(u256, &buf[n], x, .little);
        n += 1;
    }
    const torsion_bytes = [_]u8{
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
        0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
        0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    };
    const t8 = Edwards25519.fromBytes(torsion_bytes) catch unreachable;
    var q = t8;
    for (1..8) |_| {
        buf[n] = montgomeryU(q);
        const v = std.mem.readInt(u256, &buf[n], .little);
        n += 1;
        if (v + p < (1 << 255)) {
            std.mem.writeInt(u256, &buf[n], v + p, .little);
            n += 1;
        }
        q = q.add(t8);
    }
    return buf[0..n];
}

test "P6 X25519: edge u-coordinates and low-order points agree with std, every backend" {
    defer test_hooks.forced = null;
    var buf: [40][32]u8 = undefined;
    const us = edgeUs(&buf);
    // The low-order points really are: std answers error.IdentityElement.
    var low_order: usize = 0;
    const k = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    for (us) |u| {
        if (std.crypto.dh.X25519.scalarmult(k, u)) |_| {} else |_| low_order += 1;
    }
    try testing.expect(low_order >= 6); // 0, 1, p−1, p, p+1 and the order-4/8 points
    var n: u32 = 0;
    for (all_x25519_backends) |b| {
        if (!test_hooks.available(b)) continue;
        for (us) |u| {
            for (0..8) |i| {
                var wide: [64]u8 = undefined;
                std.crypto.hash.sha2.Sha512.hash(std.mem.asBytes(&n), &wide, .{});
                n += 1;
                var sk = wide[0..32].*;
                if (i == 0) sk = @splat(0);
                if (i == 1) sk = @splat(0xff);
                try expectScalarmultMatchesStd(b, sk, u);
                // RFC 7748 §5: the top bit of u is ignored
                var u_hi = u;
                u_hi[31] |= 0x80;
                try expectScalarmultMatchesStd(b, sk, u_hi);
            }
        }
    }
}

test "P6 X25519: randomized differential vs std over raw scalars and raw u (thousands, every backend)" {
    defer test_hooks.forced = null;
    const trials: usize = if (builtin.mode == .Debug) 300 else 5000;
    var prng = std.Random.DefaultPrng.init(0x7748_0006);
    const random = prng.random();
    for (all_x25519_backends) |b| {
        if (b == .stdlib or !test_hooks.available(b)) continue;
        for (0..trials) |_| {
            var k: [32]u8 = undefined;
            var u: [32]u8 = undefined;
            random.bytes(&k);
            random.bytes(&u); // raw: top bit set half the time, a few non-canonical
            try expectScalarmultMatchesStd(b, k, u);
        }
    }
}

// Field level: every 4×64 operation against u512 arithmetic mod p.

const p25519: u512 = (1 << 255) - 19;

fn limbsOf(x: u256) fe64.Limbs {
    return .{ @truncate(x), @truncate(x >> 64), @truncate(x >> 128), @truncate(x >> 192) };
}

fn canonical(a: fe64.Limbs) u512 {
    const bytes = fe64.toBytes(&a);
    return std.mem.readInt(u256, &bytes, .little);
}

/// Values that sit on every limb boundary and around p, 2p and 2^256.
const field_edges = blk: {
    const p: u256 = (1 << 255) - 19;
    break :blk [_]u256{
        0,              1,                  2,                  18,                                                                                19,                                                                                37,
        38,             39,                 p - 1,              p,                                                                                 p + 1,                                                                             p + 18,
        (1 << 255) - 1, 1 << 255,           2 * p - 1,          2 * p,                                                                             2 * p + 1,                                                                         2 * p + 37,
        ~@as(u256, 0),  ~@as(u256, 0) - 37, ~@as(u256, 0) - 38, (1 << 64) - 1,                                                                     1 << 64,                                                                           (1 << 128) - 1,
        1 << 128,       (1 << 192) - 1,     1 << 192,           0xffff_ffff_ffff_ffff_0000_0000_0000_0000_ffff_ffff_ffff_ffff_0000_0000_0000_0000, 0x8000_0000_0000_0000_8000_0000_0000_0000_8000_0000_0000_0000_8000_0000_0000_0000,
        0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffec, // p − 1 spelled out
    };
};

/// One operation on fresh copies of `x`, `y` in slots `p`, `q`; `o` chooses
/// the output slot, so the aliasing cases (`o` = an input) run too.
fn fieldOp(comptime adx: bool, comptime op: enum { mul, sq, add, sub, mul121665, invert }, comptime o: fe64.Slot, x: u256, y: u256) u512 {
    const F = fe64.Ops(adx);
    var st: fe64.State = undefined;
    for (&st) |*l| l.* = .{ 0xdead, 0xbeef, 0xdead, 0xbeef }; // no stale answer to find
    st[@intFromEnum(fe64.Slot.p)] = limbsOf(x);
    st[@intFromEnum(fe64.Slot.q)] = limbsOf(y);
    switch (op) {
        .mul => F.fmul(&st, o, .p, .q),
        .sq => F.sq(&st, o, .p),
        .add => F.add(&st, o, .p, .q),
        .sub => F.sub(&st, o, .p, .q),
        .mul121665 => F.mul121665(&st, o, .p),
        .invert => F.invert(&st, o, .p),
    }
    return canonical(st[@intFromEnum(o)]);
}

fn checkFieldPair(comptime adx: bool, x: u256, y: u256) !void {
    const X: u512 = x;
    const Y: u512 = y;
    const want_mul = (X * Y) % p25519;
    const want_sq = (X * X) % p25519;
    const want_add = (X + Y) % p25519;
    const want_sub = (X % p25519 + p25519 - Y % p25519) % p25519;
    const want_a24 = (X * 121665) % p25519;
    const cases = [_]struct { name: []const u8, got: u512, want: u512 }{
        .{ .name = "mul", .got = fieldOp(adx, .mul, .r, x, y), .want = want_mul },
        .{ .name = "sq", .got = fieldOp(adx, .sq, .r, x, y), .want = want_sq },
        .{ .name = "sq in place", .got = fieldOp(adx, .sq, .p, x, y), .want = want_sq },
        .{ .name = "add", .got = fieldOp(adx, .add, .r, x, y), .want = want_add },
        .{ .name = "add o=a", .got = fieldOp(adx, .add, .p, x, y), .want = want_add },
        .{ .name = "add o=b", .got = fieldOp(adx, .add, .q, x, y), .want = want_add },
        .{ .name = "sub", .got = fieldOp(adx, .sub, .r, x, y), .want = want_sub },
        .{ .name = "sub o=a", .got = fieldOp(adx, .sub, .p, x, y), .want = want_sub },
        .{ .name = "sub o=b", .got = fieldOp(adx, .sub, .q, x, y), .want = want_sub },
        .{ .name = "mul121665", .got = fieldOp(adx, .mul121665, .r, x, y), .want = want_a24 },
        .{ .name = "mul121665 in place", .got = fieldOp(adx, .mul121665, .p, x, y), .want = want_a24 },
        .{ .name = "toBytes", .got = canonical(limbsOf(x)), .want = X % p25519 },
    };
    for (cases) |c| if (c.got != c.want) {
        std.debug.print("adx={} {s}: x={x} y={x}\n  got  {x}\n  want {x}\n", .{ adx, c.name, x, y, c.got, c.want });
        return error.TestExpectedEqual;
    };
    if (adx) { // the ADX multiplication may write over an input
        try testing.expectEqual(want_mul, fieldOp(adx, .mul, .p, x, y));
        try testing.expectEqual(want_mul, fieldOp(adx, .mul, .q, x, y));
    }
}

test "P6 fe64: mul/sq/add/sub/mul121665/toBytes vs u512 mod p, edges × edges and random, every asm path" {
    if (!fe64.bmi2) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0xfe64_2559);
    const random = prng.random();
    const trials: usize = if (builtin.mode == .Debug) 3000 else 100_000;
    inline for (.{ false, true }) |adx| {
        if (comptime (if (adx) fe64.adx else fe64.bmi2)) {
            for (field_edges) |x| for (field_edges) |y| try checkFieldPair(adx, x, y);
            for (0..trials) |i| {
                var x = random.int(u256);
                var y = random.int(u256);
                // bias two thirds of the draws towards saturated limbs, where
                // every carry chain runs its full length
                if (i % 3 == 1) x |= ~@as(u256, 0) << @intCast(random.uintLessThan(u9, 256));
                if (i % 3 == 2) y = ~(random.int(u256) & random.int(u256) & random.int(u256));
                try checkFieldPair(adx, x, y);
                try checkFieldPair(adx, x, field_edges[i % field_edges.len]);
            }
        }
    }
}

test "P6 fe64: invert is z^(p-2) — z·z⁻¹ ≡ 1, and 0, p ↦ 0" {
    if (!fe64.bmi2) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x1_2559);
    const random = prng.random();
    inline for (.{ false, true }) |adx| {
        if (comptime (if (adx) fe64.adx else fe64.bmi2)) {
            for (0..field_edges.len + 64) |i| {
                const x = if (i < field_edges.len) field_edges[i] else random.int(u256);
                const inv = fieldOp(adx, .invert, .r, x, 0);
                const X: u512 = x;
                if (X % p25519 == 0) {
                    try testing.expectEqual(@as(u512, 0), inv);
                } else {
                    try testing.expectEqual(@as(u512, 1), (inv * (X % p25519)) % p25519);
                }
            }
        }
    }
}

test "P6 X25519: scalarmult keeps std's signature (drop-in for qap's TLS shim)" {
    try testing.expectEqual(@TypeOf(std.crypto.dh.X25519.scalarmult), @TypeOf(X25519.scalarmult));
}
