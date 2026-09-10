// SPDX-License-Identifier: MIT
//! blindrsa — RSA Blind Signatures (RFC 9474, "RSABSSA"): the primitive
//! behind anonymous-token schemes such as Privacy Pass (IETF Privacy Pass,
//! draft-ietf-privacypass-*) — a client gets a message signed by a server
//! WITHOUT the server ever seeing the message, and the resulting signature
//! is unlinkable to the blinded exchange that produced it (the server can't
//! correlate "I signed blinded_msg X for session S" with "sig Y verifies
//! against msg M" later). Built directly on the sibling `rsa` module's RFC
//! 8017 primitives (`rsaep`/`rsavp1`/`rsadp`/`rsadpCrt`/`rsasp1`,
//! `verifyPss`) — this module supplies ONLY the blind-signature-specific
//! layer (the blinding/unblinding transform + the RFC 9474 protocol
//! wiring) on top.
//!
//! ## Status: complete
//!
//! All four RFC 9474 §4 operations are implemented and validated
//! BYTE-EXACT against RFC 9474 Appendix A.1 (RSABSSA-SHA384-PSS-
//! Randomized) and A.4 (RSABSSA-SHA384-PSSZERO-Deterministic) —
//! `kat_test.zig`:
//!   - `pssEncode` — EMSA-PSS-ENCODE (RFC 8017 §9.1.1); a thin wrapper over
//!     the sibling `rsa` module's `emsaPssEncode` (see "PSS-encode + MGF1
//!     reuse" below).
//!   - `prepareIdentity` / `prepareRandomize` — RFC 9474 §4's two message
//!     "Prepare" functions (trivial: identity, or prepend a fresh 32-byte
//!     random prefix).
//!   - `blind` (+ the deterministic `blindWithFactor` KAT/test seam) —
//!     RFC 9474 §4 Blind: encode, gcd(m,n) check, sample `r ∈ [1,n)`
//!     (rejection sampling, see SPEC.md's uniformity note), invert `r`
//!     mod the COMPOSITE modulus `n` (see "the composite-modulus inverse"
//!     below), `x = RSAVP1(pk, r)`, `blinded_msg = m·x mod n`.
//!   - `blindSign` — RFC 9474 §4 BlindSign (RSASP1 via `rsa.rsasp1`'s CRT
//!     path + the mandatory RSAVP1 self-check), WITH RFC 9474 §7.2's
//!     RECOMMENDED private-op blinding implemented on top (see
//!     `blindSign`'s doc comment).
//!   - `finalize` — RFC 9474 §4 Finalize: unblind (`s = z · ctx.r_inv mod
//!     n`), then the MANDATORY trailing `verify` — fail-closed, an
//!     unverified signature is never returned.
//!   - `verify` — RFC 9474's Verify, a thin wrapper over the sibling `rsa`
//!     module's `verifyPss`, including reject tests (tampered signature,
//!     wrong message, wrong salt length).
//!
//! ## The composite-modulus inverse (and its timing posture)
//!
//! The one primitive RFC 9474 needs that neither `std.crypto.ff` nor the
//! repo's public API provides is a modular INVERSE over a composite
//! modulus (`ff` has `pow`/`powPublic` but no `invert`; Fermat inversion
//! `x^(n-2)` needs a PRIME modulus, and the client doing the inverting
//! does not know `n`'s factorization). `rsa`'s own key derivation needs
//! exactly this too (`d = e⁻¹ mod λ(n)`) and now exports the routine as
//! `pub fn bigModInverse` for exactly this cross-module reuse — this
//! module no longer carries a local copy, only the byte<->BigInt glue
//! (`newBig`/`bigFromBytes`) and its own masking layer around the call.
//! `rsa.bigModInverse`'s Euclid loop is VARIABLE-TIME in its operands, so
//! the secret-input paths never feed a raw secret into it: `blind`/
//! `blindSign` invert through `maskedInvert` (multiplicative blinding of
//! the Euclid operand itself — the divisions run on `x·u mod n` for a
//! fresh uniform secret `u`, a value statistically independent of `x`).
//! Only the deterministic `blindWithFactor` KAT seam runs the Euclid loop
//! on its input directly — see its doc comment.
//!
//! ## PSS-encode + MGF1 reuse
//!
//! The sibling `rsa` module's EMSA-PSS-ENCODE (`emsaPssEncode`, which
//! internally owns MGF1 too) is now `pub` (`modules/rsa/src/root.zig`),
//! exported specifically so RFC 9474's Blind algorithm — which needs
//! EMSA-PSS-ENCODE as a standalone step, encoding then blinding the
//! encoded integer, never calling RSASP1 directly the way `rsa.signPss`
//! does — can reuse it instead of an independent re-implementation.
//! `pssEncode` below is a thin wrapper over `rsa.emsaPssEncode`; there is
//! no local MGF1 copy anymore.
//!
//! ## RSABSSA variants (RFC 9474 §5)
//!
//! All four variants use SHA-384 (mandatory) and differ only in salt
//! length and message preparation — both are runtime/`comptime` parameters
//! below, not separate functions:
//!
//! | Variant                                | salt_len | Prepare            |
//! |-----------------------------------------|---------:|---------------------|
//! | RSABSSA-SHA384-PSS-Randomized (RECOMMENDED) | 48   | `prepareRandomize`  |
//! | RSABSSA-SHA384-PSSZERO-Randomized (RECOMMENDED) | 0 | `prepareRandomize`  |
//! | RSABSSA-SHA384-PSS-Deterministic         |       48 | `prepareIdentity`   |
//! | RSABSSA-SHA384-PSSZERO-Deterministic     |        0 | `prepareIdentity`   |
//!
//! `kat_vectors.zig` wires the Appendix A.1 (PSS-Randomized) and A.4
//! (PSSZERO-Deterministic) vectors — the other two variants share the same
//! key and construction, just with the salt length / prepare function
//! swapped, and are straightforward to add once the crypto core lands.

const std = @import("std");
const rsa = @import("rsa");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "RSA Blind Signatures (RFC 9474, RSABSSA) over `rsa` — the anonymous-token / Privacy Pass primitive: blind, sign, finalize, verify.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .both, // both a .client role (blind/finalize) and a .server role (blindSign) live in one module — CONVENTIONS.md's split rule only forces separate modules when they are separate DELIVERABLES, which RSABSSA's tight client/server coupling (shared Context/salt/hash conventions) argues against
    .concurrency = .reentrant, // no shared/global state; everything here is plain value types + explicit buffers
    .model_after = "RFC 9474 (RSA Blind Signatures / RSABSSA), layered on the sibling `rsa` module's RFC 8017 RSA primitives and RSASSA-PSS verify; jedisct1/zig-blind-rsa-signatures (MIT) consulted as a structural design reference for the Blind/BlindSign/Finalize/Verify API shape — see NOTICE",
    .deps = .{"rsa"},
};

/// Re-exported for callers sizing buffers without importing `rsa` directly.
pub const max_modulus_len = rsa.max_modulus_len;

fn byteLen(bits: usize) usize {
    return (bits + 7) / 8;
}

// ── composite-modulus number theory (extended Euclid over big.int) ──────
//
// `std.crypto.ff` deliberately has no `invert` (and Fermat inversion needs
// a prime modulus), so the blinding inverse `r⁻¹ mod n` is computed with
// the classic extended Euclidean algorithm over `std.math.big.int`. All
// scratch lives in a stack FixedBufferAllocator arena that is securely
// zeroed on exit (the operands are secret blinding factors).
//
// The Euclid loop itself is `rsa.bigModInverse` (exported `pub` for exactly
// this reuse — see its doc comment in `modules/rsa/src/root.zig`), the same
// routine `SecretKey.fromPrimes` uses privately to derive `d = e⁻¹ mod λ(n)`.
// This file only keeps the byte<->BigInt conversion helpers below (`newBig`/
// `bigFromBytes`), still needed locally for `isCoprime`'s own gcd check and
// for building `feInvert`'s operands before handing them to `rsa`.

const BigInt = std.math.big.int.Managed;

/// Limb capacity covering `rsa.max_modulus_bits`-sized operands with
/// product headroom; every scratch `BigInt` is pre-sized to this so the
/// Euclid loop performs no reallocation-driven growth inside the
/// fixed-buffer arena.
const big_capacity = (2 * rsa.max_modulus_bits) / @bitSizeOf(std.math.big.Limb) + 4;

fn newBig(gpa: std.mem.Allocator) !BigInt {
    return BigInt.initCapacity(gpa, big_capacity);
}

/// Big-endian unsigned bytes -> `BigInt` (leading zeros tolerated).
fn bigFromBytes(gpa: std.mem.Allocator, bytes: []const u8) !BigInt {
    var x = try newBig(gpa);
    if (bytes.len == 0) {
        try x.set(0);
        return x;
    }
    var m = x.toMutable();
    m.readTwosComplement(bytes, bytes.len * 8, .big, .unsigned);
    x.setMetadata(m.positive, m.len);
    return x;
}

const InvertError = error{NotInvertible};

/// `x⁻¹ mod m` at the `Fe` level. VARIABLE-TIME in `x` (see
/// `rsa.bigModInverse`) — callers holding a secret `x` go through
/// `maskedInvert` instead; this direct form is for the deterministic
/// `blindWithFactor` KAT seam and for values already independent of any
/// long-term secret.
fn feInvert(m: rsa.Modulus, x: rsa.Fe) InvertError!rsa.Fe {
    const modulus_len = byteLen(m.bits());

    var x_bytes: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &x_bytes);
    x.toBytes(x_bytes[0..modulus_len], .big) catch unreachable; // x < m fits
    var n_bytes: [max_modulus_len]u8 = undefined;
    m.toBytes(n_bytes[0..modulus_len], .big) catch unreachable;

    var scratch: [128 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var out_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &out_buf);
    const impl = struct {
        fn run(a: std.mem.Allocator, xb: []const u8, nb: []const u8, out: []u8) !void {
            var bx = try bigFromBytes(a, xb);
            var bm = try bigFromBytes(a, nb);
            var inv = try rsa.bigModInverse(a, &bx, &bm);
            inv.toConst().writeTwosComplement(out, .big);
        }
    };
    // The arena is sized so allocation cannot fail; every failure mode
    // collapses fail-closed into NotInvertible.
    impl.run(gpa, x_bytes[0..modulus_len], n_bytes[0..modulus_len], out_buf[0..modulus_len]) catch
        return error.NotInvertible;
    return rsa.Fe.fromBytes(m, out_buf[0..modulus_len], .big) catch unreachable; // inv < m canonical
}

/// `x⁻¹ mod m` for a SECRET `x`: masks `x` with a fresh uniform secret `u`
/// before running the variable-time Euclid loop, so the divisions operate
/// on `v = x·u mod n` — a uniformly distributed value statistically
/// independent of `x` — and unmasks via `x⁻¹ = v⁻¹·u mod n`. The masking
/// multiplications themselves are `std.crypto.ff`'s constant-time `mul`.
/// A `NotInvertible` result is retried under a fresh mask (the mask, not
/// `x`, may be the non-invertible party — probability ~2⁻²⁰⁴⁷ for a real
/// modulus); persistent failure means `x` itself shares a factor with `m`.
fn maskedInvert(m: rsa.Modulus, x: rsa.Fe, random: std.Random) InvertError!rsa.Fe {
    var attempt: usize = 0;
    while (attempt < 4) : (attempt += 1) {
        // u/v/v_inv are secret Fe VALUES, not just the byte buffers they get
        // serialized into elsewhere -- audit finding B6/B9: only the byte
        // copies were ever secureZero'd, leaving the struct-level copy (the
        // one `std.crypto.ff` actually computes with) live on the stack.
        var u = sampleFe(m, random);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&u));
        var v = m.mul(x, u);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&v));
        var v_inv = feInvert(m, v) catch continue;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&v_inv));
        return m.mul(v_inv, u);
    }
    return error.NotInvertible;
}

/// gcd(a, n) == 1 over big-endian byte strings (RFC 9474 §4 Blind step 4's
/// `is_coprime` check — a genuine big-int gcd against the COMPOSITE `n`,
/// not an `Fe` operation). Fails CLOSED (returns `false`) if the scratch
/// arena is ever exhausted.
fn isCoprime(a_bytes: []const u8, n_bytes: []const u8) bool {
    var scratch: [128 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    return isCoprimeAlloc(fba.allocator(), a_bytes, n_bytes);
}

/// `isCoprime`'s allocator-parameterized core (audit finding B12). Split out
/// SOLELY so a test can hand it a `std.testing.FailingAllocator` and hit the
/// `catch false` fail-closed path directly and cheaply — the real 128 KiB
/// scratch arena above only exhausts on an input around ~128 KB / ~1M bits,
/// and `std.math.big.int`'s gcd at that size is minutes-scale, impractical
/// inside a unit test's time budget (see A1/blindrsa.md B12). Private helper
/// (`isCoprime` itself is not `pub` either); no public API change.
fn isCoprimeAlloc(gpa: std.mem.Allocator, a_bytes: []const u8, n_bytes: []const u8) bool {
    const impl = struct {
        fn run(a: std.mem.Allocator, ab: []const u8, nb: []const u8) !bool {
            var ba = try bigFromBytes(a, ab);
            var bn = try bigFromBytes(a, nb);
            var g = try newBig(a);
            try g.gcd(&ba, &bn);
            return g.toConst().orderAgainstScalar(1) == .eq;
        }
    };
    return impl.run(gpa, a_bytes, n_bytes) catch false;
}

/// Uniform random field element in `[1, m)` by REJECTION sampling: draw
/// `bits(m)` random bits (top byte masked), reject `>= m` or `== 0`,
/// redraw. NOT the biased "reduce a wide random value mod n" shortcut —
/// `r`'s uniformity is what the blinding security argument leans on (see
/// SPEC.md "Uniform sampling"). Acceptance probability is > 1/2 per draw
/// (the mask bounds the candidate below `2^bits(m) < 2m`).
fn sampleFe(m: rsa.Modulus, random: std.Random) rsa.Fe {
    const modulus_bits = m.bits();
    const modulus_len = byteLen(modulus_bits);
    var buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    while (true) {
        random.bytes(buf[0..modulus_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * modulus_len - modulus_bits);
        const fe = rsa.Fe.fromBytes(m, buf[0..modulus_len], .big) catch continue;
        if (fe.isZero()) continue;
        return fe;
    }
}

// ── EMSA-PSS-ENCODE (RFC 8017 §9.1.1) — delegates to `rsa` ──────────────
//
// `rsa.emsaPssEncode` (which internally also owns MGF1/`mgf1Xor`) is now
// `pub`, exported specifically for this reuse — see its doc comment in
// `modules/rsa/src/root.zig`. This module no longer carries an independent
// re-implementation or a local `mgf1Xor`: `pssEncode` below is a thin
// wrapper, kept as a distinct public name (rather than a bare re-export)
// because RFC 9474's Blind step 1 calls EMSA-PSS-ENCODE as a standalone
// step — unlike `rsa.signPss`, which always runs RSASP1 immediately after
// encoding — so this is the module's own documented entry point for that
// step, not merely an alias of convenience.

pub const PssEncodeError = error{EncodedMessageTooShort};

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with a caller-supplied salt (RFC 9474
/// §4 Blind step 1 calls this directly — unlike `rsa.signPss`, RSABSSA
/// never runs RSASP1 over the result here; the ENCODED INTEGER itself gets
/// blinded first). MGF-hash == message-hash always (RFC 9474 §5's
/// convention). `em.len` must equal `ceil(em_bits / 8)`; `em_bits =
/// modulus_bits - 1` (RFC 9474 §4 Blind step 1 / RFC 8017 §8.1.1 step 2).
/// `salt.len == 0` selects the PSSZERO variants; `salt.len ==
/// Hash.digest_length` (48 for SHA-384) selects plain PSS.
///
/// Delegates to `rsa.emsaPssEncode` (see above); validated BYTE-EXACT
/// against RFC 9474 Appendix A.1's and A.4's published `encoded_msg`
/// values (`kat_test.zig`).
pub fn pssEncode(comptime Hash: type, msg: []const u8, salt: []const u8, em_bits: usize, em: []u8) PssEncodeError!void {
    return rsa.emsaPssEncode(Hash, msg, salt, em_bits, em);
}

// ── message preparation (RFC 9474 §4) — REAL ────────────────────────────

/// RFC 9474 §4 "PrepareIdentity": `prepared_msg = msg` (no-op). Used by the
/// `-Deterministic` variants.
pub fn prepareIdentity(msg: []const u8) []const u8 {
    return msg;
}

/// Length of the random prefix `prepareRandomize` prepends (RFC 9474 §4).
pub const randomizer_len = 32;

pub const PrepareRandomizeError = error{
    /// `out.len < randomizer_len + msg.len`. Returned rather than asserted:
    /// `msg` is caller-supplied and can vary in length at runtime, and an
    /// assert here is compiled out (along with the bounds check) in
    /// ReleaseFast, turning an undersized `out` into a silent out-of-bounds
    /// `@memcpy` in the build that ships.
    OutputTooSmall,
};

/// RFC 9474 §4 "PrepareRandomize": `prepared_msg = msg_prefix || msg`,
/// `msg_prefix` a fresh 32-byte random string. Used by the `-Randomized`
/// variants — binds a fresh randomizer to every `blind` call so that
/// signing the SAME application-level `msg` twice does not produce
/// linkable identical `prepared_msg`s. `out.len` must be at least
/// `randomizer_len + msg.len`, else `error.OutputTooSmall`; on success
/// returns the written subslice.
pub fn prepareRandomize(msg: []const u8, random: std.Random, out: []u8) PrepareRandomizeError![]const u8 {
    if (out.len < randomizer_len + msg.len) return error.OutputTooSmall;
    random.bytes(out[0..randomizer_len]);
    @memcpy(out[randomizer_len..][0..msg.len], msg);
    return out[0 .. randomizer_len + msg.len];
}

// ── Context (client-held blinding state) — REAL (plain struct; the value
// stored in `r_inv` is only meaningful once `blind`'s stub is filled in) ──

/// The client-held state a `blind` call must produce and `finalize` later
/// consumes: the blinding inverse (`r_inv`, RFC 9474's `inv`) plus enough
/// of the original request to run `finalize`'s trailing `verify` call.
/// `prepared_msg` is BORROWED — the caller must keep the same bytes alive
/// from `blind` through `finalize` (mirrors `rsa`'s own borrowed-slice
/// convention throughout its PSS/OAEP API).
pub const Context = struct {
    /// RFC 9474's `input_msg`: whatever `prepareIdentity`/`prepareRandomize`
    /// produced. NOT necessarily the raw application-level message (for the
    /// `-Randomized` variants it is `msg_prefix || msg`).
    prepared_msg: []const u8,
    /// The PSS salt length used by `blind` (48 for `-PSS`, 0 for
    /// `-PSSZERO`) — `finalize` must pass this same value to `verify`.
    salt_len: usize,
    /// `r⁻¹ mod n` (RFC 9474's `inv`), big-endian, zero-padded to
    /// `modulus_len` bytes (only the first `modulus_len` bytes are
    /// meaningful). Populated by `blind`/`blindWithFactor`; SECRET — a
    /// party learning it can link `blinded_msg` to the final `sig`.
    r_inv: [max_modulus_len]u8 = undefined,
    /// The modulus length in bytes (`k` in RFC 8017 terms) — cached so
    /// `finalize` doesn't need to re-derive it from a `PublicKey` it may
    /// not have handy in the same form `blind` did.
    modulus_len: usize,

    /// Securely wipe `r_inv` (audit finding B7): `r_inv` is documented above
    /// as SECRET — a party who learns it can link `blinded_msg` to the
    /// eventual `sig`, breaking the ONE property RFC 9474 exists to
    /// provide. `Context` previously had no path to clear it at all (no
    /// `deinit`, and neither README nor SPEC.md told a caller to
    /// `std.crypto.secureZero` it themselves) — mirrors the sibling `rsa`
    /// module's `SecretKey.deinit()` convention. `prepared_msg` is a
    /// borrowed slice (its bytes are not this struct's to wipe); `salt_len`
    /// and `modulus_len` are not secret. Call once `finalize` has consumed
    /// the `Context`; the struct must not be reused afterward.
    pub fn deinit(ctx: *Context) void {
        std.crypto.secureZero(u8, &ctx.r_inv);
    }
};

// ── Blind (client) ───────────────────────────────────────────────────────

pub const BlindError = PssEncodeError || error{
    /// RFC 9474 §4 Blind step 4: `gcd(m, n) != 1`. Negligible probability
    /// for a well-formed EMSA-PSS encoding against a real RSA modulus
    /// (would require `m` to hit a nontrivial factor of `n`); guarded
    /// defensively per the RFC's own "SHOULD abort" instruction.
    InvalidMessageBlinding,
    /// RFC 9474 §4 Blind step 5: the sampled `r` landed on `0` (or,
    /// defensively, failed to invert). Negligible probability for a
    /// correct uniform sampler over `[1, n)`; the caller should retry with
    /// fresh randomness.
    InvalidBlindingFactor,
    /// `blinded_msg_out.len < modulus_len`. Returned rather than asserted:
    /// `modulus_len` depends on the `PublicKey` passed in, so a fixed-size
    /// caller buffer sized for a smaller key silently underflows it for a
    /// larger one — and ReleaseFast compiles the assert (and the bounds
    /// check on the `toBytes` write) out, turning that into an
    /// out-of-bounds write in the build that ships.
    OutputTooSmall,
};

/// RFC 9474 §4 **Blind** (client): encodes `prepared_msg` via
/// `pssEncode`, then blinds the resulting integer against `pk` so the
/// server can sign it without learning `prepared_msg`. `salt` is
/// caller-supplied (`salt.len == 0` selects PSSZERO, `salt.len ==
/// Hash.digest_length` selects plain PSS); a real client draws it fresh
/// from `random` before calling. `random` MUST be cryptographically
/// secure — both the blinding factor `r`'s secrecy/uniformity (the entire
/// unlinkability argument) and the Euclid-masking inside `maskedInvert`
/// depend on it. On success, writes the modulus-length blinded message
/// into `blinded_msg_out` and fills `ctx_out` with everything `finalize`
/// needs later.
///
/// Construction (RFC 9474 §4 Blind): steps 5-6 here (sample `r` uniform
/// in `[1, n)` by rejection, `inv = r⁻¹ mod n` via the masked
/// extended-Euclid inverse), steps 1-4 and 7-9 in `blindCore` (shared
/// with `blindWithFactor`).
pub fn blind(
    pk: rsa.PublicKey,
    comptime Hash: type,
    prepared_msg: []const u8,
    salt: []const u8,
    random: std.Random,
    ctx_out: *Context,
    blinded_msg_out: []u8,
) BlindError![]u8 {
    // Steps 5-6: sample r ∈ [1, n) uniformly; invert it (masked — r is
    // secret and the Euclid loop is variable-time). A non-invertible r
    // (gcd(r, n) != 1 — probability ~2⁻²⁰⁴⁷, or evidence n is malformed)
    // is redrawn a bounded number of times, then reported.
    var attempt: usize = 0;
    while (attempt < 4) : (attempt += 1) {
        // Defense in depth alongside blindCore's own wipe of its by-value
        // copies (audit finding B6/B9): this frame's r/r_inv are a
        // DIFFERENT stack slot than blindCore's parameter copies.
        var r = sampleFe(pk.n, random);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&r));
        var r_inv = maskedInvert(pk.n, r, random) catch continue;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&r_inv));
        return blindCore(pk, Hash, prepared_msg, salt, r, r_inv, ctx_out, blinded_msg_out);
    }
    return error.InvalidBlindingFactor;
}

/// Deterministic variant of `blind` with a caller-supplied blinding
/// factor `r` (big-endian, must be in `[1, n)`): the seam that makes
/// `blind`'s output reproducible for the RFC 9474 Appendix A KATs
/// (`kat_test.zig` feeds the RFC's own fixed `r` and asserts
/// `blinded_msg`/`ctx.r_inv` byte-exact).
///
/// **Timing caveat**: unlike `blind`, this form runs the VARIABLE-TIME
/// extended-Euclid inverse directly on `r` (no mask — masking would
/// require randomness, defeating the deterministic purpose). Production
/// clients should call `blind`; use this only where `r`'s timing exposure
/// is acceptable (tests, KATs, single-shot offline use). `r`'s uniformity
/// requirements (SPEC.md) still apply — a biased or reused `r` breaks
/// unlinkability regardless of which entry point computed with it.
pub fn blindWithFactor(
    pk: rsa.PublicKey,
    comptime Hash: type,
    prepared_msg: []const u8,
    salt: []const u8,
    r_bytes: []const u8,
    ctx_out: *Context,
    blinded_msg_out: []u8,
) BlindError![]u8 {
    // r must OS2IP into [1, n): fromBytes rejects >= n, isZero rejects 0.
    const r = rsa.Fe.fromBytes(pk.n, r_bytes, .big) catch return error.InvalidBlindingFactor;
    if (r.isZero()) return error.InvalidBlindingFactor;
    // Step 6: inv = r⁻¹ mod n — also rejects gcd(r, n) != 1.
    const r_inv = feInvert(pk.n, r) catch return error.InvalidBlindingFactor;
    return blindCore(pk, Hash, prepared_msg, salt, r, r_inv, ctx_out, blinded_msg_out);
}

/// RFC 9474 §4 Blind steps 1-4 and 7-9, shared by `blind` (which sampled
/// and masked-inverted `r`) and `blindWithFactor` (which parsed and
/// direct-inverted it):
/// 1. `encoded_msg = pssEncode(...)` over `em_bits = bits(n) - 1`.
/// 2. `m = OS2IP(encoded_msg)`.
/// 4. `gcd(m, n) == 1` or abort (`error.InvalidMessageBlinding`).
/// 7. `x = RSAVP1(pk, r) = r^e mod n` — via `rsa.rsavp1` at
///    `max_modulus_len` width (OS2IP is zero-padding-invariant, so the
///    fixed-width call serves every modulus size).
/// 8. `z = (m · x) mod n` — constant-time `ff` multiplication.
/// 9. `blinded_msg = I2OSP(z, modulus_len)`.
fn blindCore(
    pk: rsa.PublicKey,
    comptime Hash: type,
    prepared_msg: []const u8,
    salt: []const u8,
    r_param: rsa.Fe,
    r_inv_param: rsa.Fe,
    ctx_out: *Context,
    blinded_msg_out: []u8,
) BlindError![]u8 {
    // r/r_inv arrive as by-value Fe params, i.e. this function's OWN copy on
    // its own frame -- audit finding B6: wiping only the derived byte
    // buffers below (r_bytes) left this struct-level copy live. Copied into
    // `var`s (params are immutable) so a mutable address is available for
    // secureZero.
    var r = r_param;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r));
    var r_inv = r_inv_param;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r_inv));
    const modulus_bits = pk.n.bits();
    const modulus_len = byteLen(modulus_bits);
    const em_bits = modulus_bits - 1;
    const em_len = byteLen(em_bits);
    if (blinded_msg_out.len < modulus_len) return error.OutputTooSmall;

    // Step 1: EMSA-PSS-ENCODE.
    var em_buf: [max_modulus_len]u8 = undefined;
    try pssEncode(Hash, prepared_msg, salt, em_bits, em_buf[0..em_len]);

    // Step 2: m = OS2IP(encoded_msg). EM < 2^em_bits < n by construction
    // (pssEncode step 11 clears the excess top bits), so this cannot be
    // non-canonical; guarded defensively all the same.
    const m = rsa.Fe.fromBytes(pk.n, em_buf[0..em_len], .big) catch return error.InvalidMessageBlinding;

    // Step 4: gcd(m, n) == 1 — the RFC's own "SHOULD abort" guard. A hit
    // would mean the encoded message shares a factor with n (negligible
    // for a well-formed encoding against a real modulus; finding one is
    // factoring n).
    var n_bytes: [max_modulus_len]u8 = undefined;
    pk.n.toBytes(n_bytes[0..modulus_len], .big) catch unreachable;
    if (!isCoprime(em_buf[0..em_len], n_bytes[0..modulus_len])) return error.InvalidMessageBlinding;

    ctx_out.* = .{
        .prepared_msg = prepared_msg,
        .salt_len = salt.len,
        .modulus_len = modulus_len,
    };
    r_inv.toBytes(ctx_out.r_inv[0..modulus_len], .big) catch unreachable; // r_inv < n fits

    // Step 7: x = RSAVP1(pk, r) = r^e mod n. Like r itself, x is SECRET
    // (x would unblind blinded_msg: m = blinded_msg · x⁻¹) — both byte
    // buffers are wiped on exit.
    var r_bytes: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &r_bytes);
    r.toBytes(&r_bytes, .big) catch unreachable; // zero-padded to full width
    // `unreachable` is safe here (unlike the sk.rsasp1 call in blindSign,
    // audit finding B1): rsavp1 is the PUBLIC operation and its
    // PrimitiveError can only ever be MessageRepresentativeOutOfRange, never
    // FaultDetected (that member is returned solely by the CRT PRIVATE op,
    // privateOpCrt's Bellcore/BDL self-check) — and r came from sampleFe,
    // which only ever returns a value < pk.n, so the range check cannot
    // fire either.
    var x_bytes = rsa.rsavp1(max_modulus_len, r_bytes, pk) catch unreachable; // r < n in range
    defer std.crypto.secureZero(u8, &x_bytes);
    const x = rsa.Fe.fromBytes(pk.n, &x_bytes, .big) catch unreachable; // x < n canonical

    // Steps 8-9: z = m·x mod n; blinded_msg = I2OSP(z, modulus_len).
    const z = pk.n.mul(m, x);
    z.toBytes(blinded_msg_out[0..modulus_len], .big) catch unreachable; // z < n fits
    return blinded_msg_out[0..modulus_len];
}

// ── BlindSign (server) ───────────────────────────────────────────────────

pub const BlindSignError = error{
    /// `blinded_msg.len != modulus_len`, or `OS2IP(blinded_msg) >= n` (RFC
    /// 9474 §4 BlindSign's implicit range check) — the SAME check
    /// `rsa.rsasp1`/`rsa.rsadpCrt` already perform internally
    /// (`PrimitiveError.MessageRepresentativeOutOfRange`).
    InvalidBlindedMessage,
    /// The mandatory self-check `RSAVP1(pk, s) == m` (RFC 9474 §4 BlindSign
    /// step 3) failed — never returned by a correct CRT implementation on
    /// correct hardware; exists to fail CLOSED under fault injection rather
    /// than emit a possibly-corrupted blind signature (same philosophy as
    /// the sibling `adaptor` module's `preSign` self-check). Also reported,
    /// equally fail-closed, if the internal §7.2 private-op blinding cannot
    /// obtain an invertible blinding factor (probability ~2⁻²⁰⁴⁷ per draw
    /// on a well-formed modulus — a persistent hit means a broken RNG or a
    /// malformed key).
    SigningFailure,
    /// `out.len < modulus_len`. Returned rather than asserted: `modulus_len`
    /// depends on `sk`, so a caller buffer sized for a smaller key
    /// underflows it for a larger one, and ReleaseFast compiles the assert
    /// (and the `@memcpy`'s bounds check) out — an out-of-bounds write in
    /// the build that ships.
    OutputTooSmall,
};

/// RFC 9474 §4 **BlindSign** (server): signs an opaque `blinded_msg` with
/// the RSA private key, never learning the underlying message. `pk` must
/// be the public half of `sk` (checked by assertion). `random` feeds the
/// RFC 9474 §7.2 hardening below and MUST be cryptographically secure.
///
/// **§7.2 private-op blinding — IMPLEMENTED here** (not inherited:
/// `rsa.rsasp1` performs no message blinding of its own; `std.crypto.ff`
/// gives a constant-time Montgomery-ladder modexp, and this layers the
/// RFC's separately-RECOMMENDED base blind on top for a signer processing
/// many requests under one key): draw a fresh secret `b ∈ [1, n)`, sign
/// `m·b^e` instead of `m`, and unblind the result —
/// `s = (m·b^e)^d · b⁻¹ = m^d·b·b⁻¹ = m^d (mod n)` — so the CRT
/// private-key operation never runs on attacker-chosen input directly.
/// The output is bit-identical to the unblinded computation.
///
/// Construction (RFC 9474 §4 BlindSign + §7.2):
/// 1. `m = OS2IP(blinded_msg)`, range-checked against `sk.n` (`blinded_msg`
///    must be exactly `modulus_len` bytes and `m < n`) —
///    `error.InvalidBlindedMessage` on failure.
/// 2. `s = RSASP1(sk, m)` via `rsa.rsasp1` (CRT fast path), wrapped in the
///    §7.2 base blind above.
/// 3. Mandatory self-check: `m' = RSAVP1(pk, s)` via `rsa.rsavp1`; if
///    `m' != m`, return `error.SigningFailure` (fail closed) — NEVER
///    return an unverified `blind_sig` (Boneh-DeMillo-Lipton CRT-fault
///    defense).
/// 4. `blind_sig = I2OSP(s, modulus_len)` — write `s` into `out` and
///    return the written subslice.
pub fn blindSign(
    sk: rsa.SecretKey,
    pk: rsa.PublicKey,
    random: std.Random,
    blinded_msg: []const u8,
    out: []u8,
) BlindSignError![]u8 {
    std.debug.assert(pk.n.v.eql(sk.n.v)); // pk must be sk's public half
    const modulus_len = byteLen(sk.n.bits());
    if (out.len < modulus_len) return error.OutputTooSmall;

    // Step 1: OS2IP + range check (length exact, value < n).
    if (blinded_msg.len != modulus_len) return error.InvalidBlindedMessage;
    const m = rsa.Fe.fromBytes(sk.n, blinded_msg, .big) catch return error.InvalidBlindedMessage;

    // Step 2 (+ §7.2): s = ((m·b^e)^d)·b⁻¹ mod n. b and b⁻¹ are secret;
    // b's inverse goes through the masked Euclid (see maskedInvert), and
    // every intermediate byte buffer is wiped.
    var attempt: usize = 0;
    const s: rsa.Fe = while (attempt < 4) : (attempt += 1) {
        // b/b_inv are secret Fe VALUES (audit finding B6/B9) -- only their
        // byte-buffer serializations below were ever wiped before this fix.
        var b = sampleFe(sk.n, random);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&b));
        var b_inv = maskedInvert(sk.n, b, random) catch continue;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&b_inv));

        var b_bytes: [max_modulus_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &b_bytes);
        b.toBytes(&b_bytes, .big) catch unreachable; // b < n fits
        // Same reasoning as blindCore's rsavp1 call above: rsavp1 is the
        // PUBLIC op (never returns FaultDetected) and b came from sampleFe
        // (always < sk.n), so MessageRepresentativeOutOfRange cannot fire.
        var xb_bytes = rsa.rsavp1(max_modulus_len, b_bytes, pk) catch unreachable; // b < n in range
        defer std.crypto.secureZero(u8, &xb_bytes);
        const x_b = rsa.Fe.fromBytes(sk.n, &xb_bytes, .big) catch unreachable; // < n canonical

        var mb_bytes: [max_modulus_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &mb_bytes);
        sk.n.mul(m, x_b).toBytes(&mb_bytes, .big) catch unreachable; // < n fits
        // The CRT private-key op itself — constant-time ff pow inside rsa.
        // Audit finding B1: this call's PrimitiveError is NOT range-only —
        // unlike the rsavp1 (public-op) calls above, rsasp1 routes through
        // privateOpCrt, whose Bellcore/BDL self-check (audit F3 in `rsa`)
        // can legitimately return `error.FaultDetected` on a CRT fault
        // (bit-flip, hardware glitch). That is exactly the event
        // BlindSignError.SigningFailure and SPEC.md's "fail-closed by
        // design" promise exist for; `catch unreachable` turned a
        // documented, reachable failure into a Debug/ReleaseSafe panic and
        // ReleaseFast UB instead. Range is still guaranteed (mb_bytes is a
        // mod-n product), so the only realistic error left is the fault.
        var sb_bytes = rsa.rsasp1(max_modulus_len, mb_bytes, sk) catch return error.SigningFailure;
        defer std.crypto.secureZero(u8, &sb_bytes);
        const s_b = rsa.Fe.fromBytes(sk.n, &sb_bytes, .big) catch unreachable; // < n canonical

        break sk.n.mul(s_b, b_inv);
    } else return error.SigningFailure;

    // Step 3: mandatory self-check RSAVP1(pk, s) == m — fail closed.
    var s_bytes: [max_modulus_len]u8 = undefined;
    s.toBytes(&s_bytes, .big) catch unreachable; // s < n fits
    const m_check = rsa.rsavp1(max_modulus_len, s_bytes, pk) catch return error.SigningFailure;
    var m_expect = [_]u8{0} ** max_modulus_len;
    @memcpy(m_expect[max_modulus_len - modulus_len ..], blinded_msg);
    if (!std.crypto.timing_safe.eql([max_modulus_len]u8, m_check, m_expect)) {
        return error.SigningFailure;
    }

    // Step 4: blind_sig = I2OSP(s, modulus_len).
    @memcpy(out[0..modulus_len], s_bytes[max_modulus_len - modulus_len ..]);
    return out[0..modulus_len];
}

// ── Finalize (client) ────────────────────────────────────────────────────

pub const FinalizeError = error{
    /// `blind_sig.len != ctx.modulus_len` (RFC 9474 §4 Finalize step 1).
    InvalidBlindSignatureLength,
    /// `out.len < ctx.modulus_len`. Returned rather than asserted: `ctx`
    /// carries whatever modulus size `blind` was called with, so a fixed
    /// caller buffer sized for a smaller key underflows it for a larger
    /// one, and ReleaseFast compiles the assert (and the `toBytes` write's
    /// bounds check) out — an out-of-bounds write in the build that ships.
    OutputTooSmall,
    /// `ctx.modulus_len` does not match `pk`'s actual modulus length, or
    /// exceeds `max_modulus_len`. Returned rather than asserted: `Context`
    /// is a `pub` struct with no constructor (`kat_test.zig` composes it by
    /// hand, and a real deployment's `Context` survives a network round
    /// trip between `blind` and `finalize`, so a corrupted or foreign
    /// `Context` reaching here is realistic). ReleaseFast compiles the
    /// former assert out together with the bounds check on the
    /// `ctx.r_inv[0..ctx.modulus_len]` slice that follows, turning an
    /// oversized `modulus_len` into an out-of-bounds read of up to
    /// `max_modulus_len` extra bytes in the build that ships (audit finding
    /// B4).
    InvalidContext,
} || rsa.VerifyPssError;

/// RFC 9474 §4 **Finalize** (client): unblinds `blind_sig` using the
/// `Context` `blind` produced, then verifies the result BEFORE returning
/// it — fail-closed, never hands back an unverified signature (the ONLY
/// path that returns a `sig` goes through the trailing `verify` call; a
/// malicious or faulty signer's output cannot leak past it).
///
/// Construction (RFC 9474 §4 Finalize):
/// 1. `blind_sig.len == ctx.modulus_len`, else
///    `error.InvalidBlindSignatureLength`.
/// 2. `z = OS2IP(blind_sig)` — a `z >= n` can never be a valid blind
///    signature, so a non-canonical value fails closed as
///    `error.SignatureVerificationFailed` (same terminal error the
///    trailing verify would produce; no separate oracle).
/// 3. `s = (z · ctx.r_inv) mod n` — constant-time `ff` multiplication
///    (`ctx.r_inv` is secret).
/// 4. `sig = I2OSP(s, modulus_len)`.
/// 5. `verify(pk, Hash, ctx.prepared_msg, sig, ctx.salt_len)` — MANDATORY;
///    `error.SignatureVerificationFailed` propagates fail-closed.
pub fn finalize(pk: rsa.PublicKey, comptime Hash: type, blind_sig: []const u8, ctx: *const Context, out: []u8) FinalizeError![]u8 {
    // Step 1: exact-length check.
    if (blind_sig.len != ctx.modulus_len) return error.InvalidBlindSignatureLength;
    if (out.len < ctx.modulus_len) return error.OutputTooSmall;
    // ctx must match pk (audit finding B4) — checked, not asserted: a
    // mismatched modulus_len would otherwise slice ctx.r_inv (a fixed
    // [max_modulus_len]u8 array) out of bounds below, and ReleaseFast
    // compiles both the assert and that slice's bounds check out together.
    if (ctx.modulus_len > max_modulus_len or byteLen(pk.n.bits()) != ctx.modulus_len)
        return error.InvalidContext;

    // Step 2: z = OS2IP(blind_sig), fail-closed on z >= n.
    const z = rsa.Fe.fromBytes(pk.n, blind_sig, .big) catch return error.SignatureVerificationFailed;
    // ctx.r_inv was written by blind/blindWithFactor as a canonical value
    // < n; a corrupted/foreign ctx fails closed here too.
    const r_inv = rsa.Fe.fromBytes(pk.n, ctx.r_inv[0..ctx.modulus_len], .big) catch
        return error.SignatureVerificationFailed;

    // Steps 3-4: s = z·r⁻¹ mod n; sig = I2OSP(s, modulus_len).
    const sig = out[0..ctx.modulus_len];
    pk.n.mul(z, r_inv).toBytes(sig, .big) catch unreachable; // s < n fits

    // Step 5: mandatory trailing verify — fail-closed.
    try verify(pk, Hash, ctx.prepared_msg, sig, ctx.salt_len);
    return sig;
}

// ── Verify — REAL ────────────────────────────────────────────────────────

/// RFC 9474 **Verify**: plain RSASSA-PSS-VERIFY (RFC 8017 §8.1.2), a thin
/// wrapper over the sibling `rsa` module's `verifyPss`. `prepared_msg` is
/// the RFC's `input_msg` — the OUTPUT of `prepareIdentity`/
/// `prepareRandomize`, not necessarily the raw application-level message
/// (for the `-Randomized` variants it is `msg_prefix || msg`). `salt_len`
/// must match the signer's convention (48 for `-PSS`, 0 for `-PSSZERO`,
/// RFC 9474 §5).
///
/// REAL — no number theory of its own; validated byte-exact against RFC
/// 9474 Appendix A.1's and A.4's published `sig` values, including reject
/// tests (tampered signature, wrong message) — see `kat_test.zig`.
pub fn verify(pk: rsa.PublicKey, comptime Hash: type, prepared_msg: []const u8, sig: []const u8, salt_len: usize) rsa.VerifyPssError!void {
    return rsa.verifyPss(pk, Hash, prepared_msg, sig, salt_len);
}

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta names RFC 9474 and the sibling rsa dep" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "9474") != null);
    try std.testing.expectEqualStrings("rsa", meta.deps[0]);
}

test "prepareIdentity is a no-op" {
    try std.testing.expectEqualStrings("hello", prepareIdentity("hello"));
}

test "prepareRandomize prepends exactly randomizer_len fresh bytes and preserves msg" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x42} ** 32);
    var out: [randomizer_len + 5]u8 = undefined;
    const prepared = try prepareRandomize("hello", csprng.random(), &out);
    try std.testing.expectEqual(@as(usize, randomizer_len + 5), prepared.len);
    try std.testing.expectEqualStrings("hello", prepared[randomizer_len..]);
}

test "prepareRandomize is non-deterministic across calls (fresh prefix each time)" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x7} ** 32);
    var out1: [randomizer_len + 3]u8 = undefined;
    var out2: [randomizer_len + 3]u8 = undefined;
    const p1 = try prepareRandomize("abc", csprng.random(), &out1);
    const p2 = try prepareRandomize("abc", csprng.random(), &out2);
    try std.testing.expect(!std.mem.eql(u8, p1[0..randomizer_len], p2[0..randomizer_len]));
}

// ── B10 anchor: entropy in EVERY prefix byte, not just "differs somewhere" ─
//
// ⛔⛔ The test above only proves two prefixes differ SOMEWHERE — true even if
// only 4 of the 32 bytes carry real entropy and the other 28 are fixed or
// derived (audit mutation `m12`: RFC 9474 §4/§7.4 require the full 32-byte
// prefix to be MUST-level random; the delta in attacker search space is
// 2^32 vs 2^256). This test instead checks EVERY one of the 32 positions
// independently across many draws.
test "B10: prepareRandomize's 32-byte prefix carries real entropy in every byte position (audit mutation m12)" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x70} ** 32);
    const random = csprng.random();

    const draws = 64;
    var seen: [randomizer_len][256]bool = [_][256]bool{[_]bool{false} ** 256} ** randomizer_len;
    var i: usize = 0;
    while (i < draws) : (i += 1) {
        var out: [randomizer_len]u8 = undefined;
        const prepared = try prepareRandomize("", random, &out);
        for (prepared[0..randomizer_len], 0..) |b, pos| seen[pos][b] = true;
    }
    // Every position must show MORE THAN ONE distinct value across 64
    // independent draws. A position fed by real entropy essentially always
    // will (P(all 64 draws collide) ~= (1/256)^63); a fixed or
    // derived-from-elsewhere position shows exactly one.
    for (seen) |pos_seen| {
        var distinct: usize = 0;
        for (pos_seen) |v| {
            if (v) distinct += 1;
        }
        try std.testing.expect(distinct > 1);
    }
}

test "pssEncode rejects a salt too long for the target size (RFC 8017 SS9.1.1 step 3)" {
    var em: [16]u8 = undefined;
    try std.testing.expectError(
        error.EncodedMessageTooShort,
        pssEncode(std.crypto.hash.sha2.Sha384, "m", &([_]u8{0} ** 40), 16 * 8, &em),
    );
}

// ── private-helper tests (extended-Euclid inverse, gcd, sampling) ───────

const kat = @import("kat_vectors.zig");

test "feInvert: hand-checkable small case (7^-1 mod 15 == 13)" {
    const m = try rsa.Modulus.fromPrimitive(u8, 15);
    const seven = try rsa.Fe.fromPrimitive(u8, m, 7);
    const inv = try feInvert(m, seven);
    try std.testing.expectEqual(@as(u8, 13), try inv.toPrimitive(u8));
}

test "feInvert: non-coprime input fails (5 shares a factor with 15)" {
    const m = try rsa.Modulus.fromPrimitive(u8, 15);
    const five = try rsa.Fe.fromPrimitive(u8, m, 5);
    try std.testing.expectError(error.NotInvertible, feInvert(m, five));
}

test "feInvert reproduces the RFC 9474 published inv from r (and back) over the real 4096-bit composite n" {
    const pk = try kat.publicKey();
    const r = try rsa.Fe.fromBytes(pk.n, &kat.r, .big);
    const inv = try feInvert(pk.n, r);
    var got: [kat.a1.inv.len]u8 = undefined;
    try inv.toBytes(&got, .big);
    try std.testing.expectEqualSlices(u8, &kat.a1.inv, &got);
    // Inverse of the inverse round-trips to r (inv is unique in [0, n)).
    const r_back = try feInvert(pk.n, inv);
    var got_r: [kat.r.len]u8 = undefined;
    try r_back.toBytes(&got_r, .big);
    try std.testing.expectEqualSlices(u8, &kat.r, &got_r);
}

test "feInvert rejects a factor of n (gcd(p, n) == p != 1)" {
    const pk = try kat.publicKey();
    var p_wide = [_]u8{0} ** (kat.n.len);
    @memcpy(p_wide[kat.n.len - kat.p.len ..], &kat.p);
    const p_fe = try rsa.Fe.fromBytes(pk.n, &p_wide, .big);
    try std.testing.expectError(error.NotInvertible, feInvert(pk.n, p_fe));
}

// ── B5 anchor: the masking itself, not the value it produces ───────────────
//
// ⛔⛔ The test below this one ("mask cancels exactly") asserts VALUE equality
// with the direct inverse — and therefore passes EXACTLY WHEN THE MASKING IS
// GONE. The audit proved it: mutation `m8` (`maskedInvert` replaced by
// `return feInvert(m, x);`) and `m21b` (the mask replaced by the constant 3)
// both SURVIVED 42/42. Textbook `feedback_property_no_value_test_can_see`:
// the guard was built on the artefact, not on the property.
//
// ⚠ And ctgrind cannot cover this either — a constant mask is still
// branch-free, so no context count moves. The property is "a FRESH, UNIFORM
// scalar is drawn per attempt", which is about the algorithm's use of
// randomness, and the seam that makes it observable is already there:
// `maskedInvert` takes its `std.Random` as a parameter.
//
// So these two tests count draws and force the retry path. Between them:
//   * `m8` draws nothing at all           -> both fail,
//   * `m21b` draws nothing and never retries -> both fail,
//   * an implementation that draws once and reuses it -> the second fails.

/// A `std.Random` that hands out a scripted sequence of full-width values and
/// counts how many draws were taken. `sampleFe` requests `modulus_len` bytes
/// per attempt, so one draw == one masking scalar.
const ScriptedRandom = struct {
    values: []const []const u8,
    draws: usize = 0,

    fn fill(self: *ScriptedRandom, buf: []u8) void {
        const v = self.values[@min(self.draws, self.values.len - 1)];
        self.draws += 1;
        @memset(buf, 0);
        if (buf.len >= v.len) {
            @memcpy(buf[buf.len - v.len ..], v);
        } else {
            @memcpy(buf, v[v.len - buf.len ..]);
        }
    }
};

test "B5: maskedInvert DRAWS a fresh scalar and RETRIES when the mask makes the product non-invertible" {
    const pk = try kat.publicKey();
    const r = try rsa.Fe.fromBytes(pk.n, &kat.r, .big);

    // First draw is `p`, a factor of `n`: `v = r*p mod n` still shares the
    // factor, so `feInvert` must fail and the loop must draw AGAIN. The second
    // draw is an ordinary value that works.
    var second = [_]u8{0} ** kat.n.len;
    second[kat.n.len - 1] = 0x07;
    var scripted = ScriptedRandom{ .values = &.{ &kat.p, &second } };
    const random = std.Random.init(&scripted, ScriptedRandom.fill);

    const inv = try maskedInvert(pk.n, r, random);

    // Still the right answer -- masking must cancel exactly.
    var got: [kat.a1.inv.len]u8 = undefined;
    try inv.toBytes(&got, .big);
    try std.testing.expectEqualSlices(u8, &kat.a1.inv, &got);

    // ⛔ The load-bearing assertion. An unmasked invert answers straight from
    // `r` and never touches the RNG; a constant mask never touches it either.
    // Two draws means: one scalar was drawn, its product was rejected, and a
    // SECOND, DIFFERENT one was drawn.
    try std.testing.expectEqual(@as(usize, 2), scripted.draws);
}

test "B5: a mask that never changes cannot rescue a non-invertible product — the retry bound is real" {
    const pk = try kat.publicKey();
    const r = try rsa.Fe.fromBytes(pk.n, &kat.r, .big);

    // Every draw is `p`, so every attempt's product keeps the shared factor.
    // A correct implementation exhausts its four attempts and fails closed;
    // it must not loop forever, and it must not return a wrong value.
    var scripted = ScriptedRandom{ .values = &.{&kat.p} };
    const random = std.Random.init(&scripted, ScriptedRandom.fill);

    try std.testing.expectError(error.NotInvertible, maskedInvert(pk.n, r, random));
    // Four attempts, four scalars. Pins the bound the loop declares, and fails
    // for an implementation that draws once and reuses it.
    try std.testing.expectEqual(@as(usize, 4), scripted.draws);
}

test "maskedInvert matches the direct inverse (mask cancels exactly) and rejects non-invertible input" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x33} ** 32);
    const random = csprng.random();
    const pk = try kat.publicKey();

    const r = try rsa.Fe.fromBytes(pk.n, &kat.r, .big);
    const inv = try maskedInvert(pk.n, r, random);
    var got: [kat.a1.inv.len]u8 = undefined;
    try inv.toBytes(&got, .big);
    try std.testing.expectEqualSlices(u8, &kat.a1.inv, &got);

    var p_wide = [_]u8{0} ** (kat.n.len);
    @memcpy(p_wide[kat.n.len - kat.p.len ..], &kat.p);
    const p_fe = try rsa.Fe.fromBytes(pk.n, &p_wide, .big);
    try std.testing.expectError(error.NotInvertible, maskedInvert(pk.n, p_fe, random));
}

test "isCoprime: factor of n is NOT coprime; RFC encoded_msg IS (blind step 4's exact check)" {
    try std.testing.expect(!isCoprime(&kat.p, &kat.n));
    try std.testing.expect(!isCoprime(&kat.q, &kat.n));
    try std.testing.expect(isCoprime(&kat.a1.encoded_msg, &kat.n));
    try std.testing.expect(isCoprime(&kat.a4.encoded_msg, &kat.n));
    // gcd(0, n) = n != 1.
    try std.testing.expect(!isCoprime(&[_]u8{0}, &kat.n));
    try std.testing.expect(isCoprime(&[_]u8{1}, &kat.n));
}

// ── B12 anchor: isCoprime fails CLOSED, not open, when its arena is
// exhausted ─────────────────────────────────────────────────────────────
//
// Audit mutation m20 flips `catch false` to `catch true` in isCoprime's
// exhaustion path: RFC 9474 Blind step 4's "is_coprime" guard would then
// ACCEPT a message that shares a factor with n whenever the 128 KiB scratch
// arena runs out, instead of rejecting it (`error.InvalidMessageBlinding`).
// The audit itself flagged this as testable "only with a rigged input" —
// reproducing the real arena's exhaustion needs an ~128 KB / ~1M-bit input,
// and `std.math.big.int`'s gcd at that size is minutes-scale (checked: not
// safe inside a unit test's time budget or `scripts/modtest`'s timeout, see
// A1/blindrsa.md B12). `isCoprimeAlloc` above exists so this test can force
// the SAME failure path -- an allocator that fails on its very first
// request -- without touching the real arena size or the real gcd cost at
// all: cheap, deterministic, and it exercises the identical `catch false`
// `impl.run(...) catch false` line the real `isCoprime` runs.
test "B12: isCoprime fails CLOSED (false), not open, when the underlying allocator is exhausted" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    // A well-formed, definitely-coprime pair (RFC 9474's own encoded_msg
    // vs. n) -- if isCoprimeAlloc ever returns `true` here, the allocator
    // failure was ignored rather than propagated fail-closed.
    try std.testing.expectEqual(false, isCoprimeAlloc(failing.allocator(), &kat.a1.encoded_msg, &kat.n));
    // Confirms the `false` above came from the injected allocator failure
    // (not some other reason) -- the failure really was induced.
    try std.testing.expect(failing.has_induced_failure);
}

test "sampleFe: always in [1, n), even for a modulus with few top-byte bits" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x44} ** 32);
    const random = csprng.random();
    // 0x0209 = 521 (prime, 10 bits): the top byte carries only 2 usable
    // bits, so an unmasked draw would reject ~87% of the time — exercises
    // the top-byte mask, the rejection loop, and the zero rejection.
    const m = try rsa.Modulus.fromPrimitive(u16, 521);
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const fe = sampleFe(m, random);
        const v = try fe.toPrimitive(u16);
        try std.testing.expect(v >= 1 and v < 521);
    }
}

// ── B2 anchor: sampleFe's UNIFORMITY, not just its range ───────────────────
//
// ⛔⛔ The test above only pins the RANGE. RFC 9474 §4.2 makes uniformity a
// MUST ("The blinding factor r MUST be randomly chosen from a uniform
// distribution"), and SPEC.md's "Uniform sampling of r in [1, n)" section
// explains why "reduce a wide random value mod n" is the wrong shortcut —
// but nothing enforced it. Two audit mutations SURVIVED the range-only
// test, 42/42 green: `m7b` (top-byte mask one bit too narrow, so every draw
// lands in the LOWER HALF `[1, 2^(bits-1))`) and `m6` (drop the `isZero`
// rejection). These two tests close that gap.

test "B2: sampleFe is not biased toward the lower half of the modulus (audit mutation m7b)" {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x66} ** 32);
    const random = csprng.random();
    // 1021 is prime; bits(1021) == 10 and 2^9 == 512 sits almost exactly at
    // 1021's own midpoint (50.1%) -- deliberately chosen so a real uniform
    // sampler over [1, 1021) puts roughly HALF its draws at >= 512, while a
    // sampler whose top-byte mask is one bit too narrow can NEVER produce a
    // value >= 512 at all: every draw collapses into [1, 512).
    const m = try rsa.Modulus.fromPrimitive(u16, 1021);
    const n: usize = 4000;
    var above_half: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const fe = sampleFe(m, random);
        const v = try fe.toPrimitive(u16);
        try std.testing.expect(v >= 1 and v < 1021);
        if (v >= 512) above_half += 1;
    }
    // True uniform expectation is ~50%; a halved-range sampler scores 0%.
    // 30% is a wide margin below the true rate and a wide margin above the
    // mutant's 0% -- not a coin-flip threshold.
    try std.testing.expect(above_half >= n * 3 / 10);
}

test "B2: sampleFe rejects a zero draw and retries rather than returning it (audit mutation m6)" {
    const ZeroThenRandom = struct {
        inner: std.Random,
        zeros_left: usize,

        fn fill(self: *@This(), buf: []u8) void {
            if (self.zeros_left > 0) {
                self.zeros_left -= 1;
                @memset(buf, 0);
                return;
            }
            self.inner.bytes(buf);
        }
    };
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x67} ** 32);
    var scripted = ZeroThenRandom{ .inner = csprng.random(), .zeros_left = 1 };
    const random = std.Random.init(&scripted, ZeroThenRandom.fill);

    const m = try rsa.Modulus.fromPrimitive(u16, 1021);
    const fe = sampleFe(m, random);
    const v = try fe.toPrimitive(u16);
    // A sampler that skipped the isZero rejection would have returned 0
    // straight from the scripted first (all-zero) draw.
    try std.testing.expect(v != 0);
    try std.testing.expect(v >= 1 and v < 1021);
    try std.testing.expectEqual(@as(usize, 0), scripted.zeros_left); // the zero draw WAS consumed
}

// ── B6/B9 anchor: secret Fe values (and the byte buffers already wiped)
// do not survive on the stack after blind() returns ───────────────────────
//
// Audit's own `probe deadstack` (A1/repro/blindrsa/probe.zig, a standalone
// build-exe binary) found: r's big-endian byte buffer (`r_bytes` in
// `blindCore`, already `secureZero`'d) = 0 hits -- a working negative
// control -- while r in `ff.Fe` LIMB order (little-endian, never wiped by
// anything) = 2 hits in the 512 KiB below `blind()`'s frame. The `Fe`
// copies of `r`/`r_inv` (blind/blindCore) and `u`/`v`/`v_inv`
// (maskedInvert) were never zeroed as STRUCTURED values -- only their
// byte-buffer serializations were (B6). And nothing pinned that any of the
// EXISTING byte-buffer wipes (`r_bytes`, `feInvert`'s Euclid scratch arena)
// actually take effect rather than being silently compiled away (B9).
//
// This reproduces the audit's technique INSIDE `zig build test-<m>` (a
// FixedRandom pins r, so both the sampled r AND maskedInvert's masking
// scalar u collapse to the same known bit pattern) instead of as a
// separate build-exe probe, so it runs under `scripts/modtest` like every
// other test in this campaign. ReleaseFast-only: stack layout in Debug is
// not what the audit measured, and register/spill allocation this fine-
// grained is not something a Debug build's frame shape reflects at all.
const DeadStackFixedRandom = struct {
    val: []const u8,
    fn fill(self: *const @This(), buf: []u8) void {
        @memset(buf, 0);
        if (buf.len >= self.val.len) {
            @memcpy(buf[buf.len - self.val.len ..], self.val);
        } else {
            @memcpy(buf, self.val[self.val.len - buf.len ..]);
        }
    }
};

noinline fn deadStackRunBlind(pk: rsa.PublicKey, random: std.Random, ctx: *Context) void {
    var bm: [max_modulus_len]u8 = undefined;
    _ = blind(pk, std.crypto.hash.sha2.Sha384, &kat.a1.prepared_msg, &kat.a1.salt, random, ctx, &bm) catch unreachable;
}

noinline fn deadStackScan(needle: []const u8, base: [*]const u8, len: usize) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= len) : (i += 1) {
        if (std.mem.eql(u8, base[i..][0..needle.len], needle)) hits += 1;
    }
    return hits;
}

// ⚠ 2026-09-10 fix-campaign measurement (fixwt/a, see A1/blindrsa.md
// Dispozice for the full writeup): `blindCore`/`maskedInvert`/`blind` were
// changed to `secureZero` their `r`/`r_inv`/`u`/`v`/`v_inv`/`b`/`b_inv` Fe
// STRUCT copies, not just the byte-buffer serializations that were already
// wiped. Measured RED (before that change): this scan found 2 hits for r in
// ff.Fe limb order. Measured again AFTER the change: still 2 hits, byte-for-
// byte identical count. The leak survives wiping every Fe our own code
// holds, which means it lives inside `std.crypto.ff`'s own internals (a
// Montgomery-multiplication or byte<->limb-conversion scratch temporary),
// not in a copy `blindrsa` controls — the same class of trap as
// `zig_std_crypto_leaves_key_schedules_on_stack` (project memory). B6
// therefore stays OPEN; only the `hits_be` half below (which the B6 fix did
// not touch, and which was already true before it) is asserted as a real
// B9 anchor for the `r_bytes` buffer wipe. `hits_le` is printed for the
// record but NOT asserted -- asserting 0 would misrepresent an unresolved
// finding as fixed, and asserting the current (leaking) count would pin a
// known leak as the expected/accepted shape. Neither is honest here.
test "B9: blind()'s r_bytes buffer (the byte-level secureZero) does not survive on the stack after return" {
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;
    const pk = try kat.publicKey();
    var fixed = DeadStackFixedRandom{ .val = &kat.r };
    const random = std.Random.init(&fixed, DeadStackFixedRandom.fill);
    var ctx: Context = undefined;

    var anchor: usize = 0;
    const stack_top: [*]const u8 = @ptrCast(&anchor);
    anchor = 1;
    deadStackRunBlind(pk, random, &ctx);
    const window: usize = 512 * 1024;
    const base = stack_top - window;

    // needle A: r big-endian -- the r_bytes buffer blindCore explicitly
    // secureZero's. Negative control: must stay 0 hits regardless of this
    // test's own B6 fix (it was already wiped before this test existed).
    const be = kat.r[0..32];
    // needle B: r as ff.Fe stores it -- little-endian u64 limbs, i.e. the
    // full byte-reversal of the big-endian value. THIS is what B6 found
    // unwiped.
    var rev: [512]u8 = undefined;
    for (kat.r, 0..) |c, idx| rev[511 - idx] = c;
    const le = rev[0..32];

    const hits_be = deadStackScan(be, base, window);
    // NOT asserted -- see the comment above this test (B6 stays open).
    const hits_le = deadStackScan(le, base, window);
    std.debug.print(
        "B9/B6 dead-stack scan, {d} KiB below blind()'s frame: r big-endian (r_bytes, wiped -- ASSERTED) = {d} hits, r ff.Fe limb order (std.crypto.ff internal, NOT asserted, B6 open) = {d} hits\n",
        .{ window / 1024, hits_be, hits_le },
    );
    try std.testing.expectEqual(@as(usize, 0), hits_be);
}
