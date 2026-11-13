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
//!   - `blindSign` — RFC 9474 §4 BlindSign (RSASP1 via `rsa.rsadpCrtBlinded`'s CRT
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
//! The one primitive RFC 9474 needs that `std.crypto.ff` does not provide
//! is a modular INVERSE over a composite modulus (Fermat inversion
//! `x^(n-2)` needs a PRIME modulus, and the client doing the inverting does
//! not know `n`'s factorization). Since 2026-11-13 it is
//! `montint.DynModint.inverse` on the `n_mont` every `rsa.PublicKey`
//! already carries: a batched Bernstein–Yang safegcd, constant-time in the
//! operand and in the modulus value, and the same engine `rsa`'s private-op
//! blinding uses. `blind` inverts `m·r` once (steps 4 and 6 together, see
//! `blindCore`). Before, it was `rsa.bigModInverse`'s variable-time big-int
//! Euclid behind a multiplicative mask, plus a big-int gcd for step 4 —
//! correct, but 4.6–5.0× CIRCL for `blind` as a whole.
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

// ── composite-modulus arithmetic on rsa's montint modulus ─────────────────
//
// Every client-side operation here — the blinding factor, the composite-
// modulus inverse, `r^e`, the blinding and unblinding products — runs on the
// `montint.DynModint` that `rsa.PublicKey` already carries for `n`
// (`pk.n_mont`, built once when the key is parsed). Until 2026-11-13 this
// layer was `std.crypto.ff` plus an extended Euclid over `std.math.big`
// (`rsa.bigModInverse`) behind a multiplicative mask, and a second big-int
// gcd for RFC 9474's coprimality check: variable-time, masked to compensate,
// and most of `blind`'s cost (4.6–5.5× CIRCL). `DynModint.inverse` is
// montint's batched Bernstein–Yang safegcd — constant-time in the operand and
// in the modulus value, a few tens of µs at 2048 bits, and the same engine
// `rsa`'s own private-op blinding inverts with — so neither the mask nor the
// big-int scratch arenas are needed any more.

/// `rsa.PublicKey.n_mont`'s type, `montint.DynModint(rsa.max_modulus_bits)`,
/// named through the field so this module needs no `montint` dependency of
/// its own: every operation used here is a `pub` method of that type.
const NMont = @FieldType(rsa.PublicKey, "n_mont");
/// A normal-domain element of `NMont` (`8 · max_limbs` bytes, little-endian
/// limbs, zero above the modulus's slot).
const Elem = NMont.Elem;

fn wipeElem(e: *Elem) void {
    std.crypto.secureZero(u64, e);
}

/// `pk.e` big-endian, without leading zeros (the public exponent `powPublic`
/// walks). `e < n` always fits `buf`.
fn exponentBE(pk: *const rsa.PublicKey, buf: *[max_modulus_len]u8) []const u8 {
    pk.e.toBytes(buf, .big) catch unreachable; // e < n ≤ 2^(8·max_modulus_len)
    return std.mem.trimStart(u8, buf, &.{0});
}

/// Most draws `sampleElem` makes before giving up. Each draw is accepted with
/// probability above 1/2 (and a zero is a ~2^-bits event), so an honest
/// generator needs two draws on average and misses 128 in a row with
/// probability below 2^-128; a generator that only ever yields zeros, or
/// values `>= m`, ends here instead of hanging the caller (sweep BRSA-2).
const max_sample_draws = 128;

/// Uniform random element of `[1, m)` into `out` by REJECTION sampling: draw
/// `bits(m)` random bits (top byte masked), reject `>= m` or `== 0`, redraw.
/// NOT the biased "reduce a wide random value mod n" shortcut — `r`'s
/// uniformity is what the blinding security argument leans on (see SPEC.md
/// "Uniform sampling"). Acceptance probability is > 1/2 per draw (the mask
/// bounds the candidate below `2^bits(m) < 2m`). One `random.bytes` call of
/// exactly the modulus length per attempt (the ctgrind harness and the tests
/// recognise the draw by that length). At most `max_sample_draws` draws:
/// then `error.InvalidBlindingFactor` (a broken `random`, never an honest one).
fn sampleElem(np: *const NMont, random: std.Random, out: *Elem) error{InvalidBlindingFactor}!void {
    const modulus_bits = np.bits();
    const modulus_len = byteLen(modulus_bits);
    var buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..modulus_len]);
    for (0..max_sample_draws) |_| {
        random.bytes(buf[0..modulus_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * modulus_len - modulus_bits);
        out.* = np.elemFromBytesBE(buf[0..modulus_len]) catch continue;
        if (NMont.isZero(out)) continue;
        return;
    }
    return error.InvalidBlindingFactor;
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
    /// `salt_len` was neither `0` (PSSZERO) nor `Hash.digest_length` (PSS)
    /// — the only two values RFC 9474 §5 defines. Audit finding B16: this
    /// guards the buffer `blind` draws the salt into, sized
    /// `Hash.digest_length`.
    InvalidSaltLength,
};

/// RFC 9474 §4 **Blind** (client): encodes `prepared_msg` via
/// `pssEncode`, then blinds the resulting integer against `pk` so the
/// server can sign it without learning `prepared_msg`. `salt_len == 0`
/// selects the PSSZERO variants, `salt_len == Hash.digest_length` (48 for
/// SHA-384) selects plain PSS (RFC 9474 §5) — `blind` draws the salt
/// itself, `salt_len` bytes from `random`, rather than taking it as a
/// parameter (audit finding B16: RFC 9474 §7.4 "implementations SHOULD NOT
/// allow clients to provide these values directly" — a maliciously chosen
/// salt is visible in the final signature and can carry the client's
/// identity, e.g. its own IP address per the RFC's example, without the
/// client detecting it, which defeats unlinkability, the entire point of
/// this module). Determinism for the RFC 9474 Appendix A KATs (whose fixed
/// `r` this function cannot take) lives in `blindWithFactor`, which keeps
/// the `salt` parameter for exactly that reason. `random` MUST be
/// cryptographically secure — the salt and the blinding factor `r`'s
/// secrecy/uniformity (the entire unlinkability argument) depend on it. On success,
/// writes the modulus-length blinded message into `blinded_msg_out` and
/// fills `ctx_out` with everything `finalize` needs later.
///
/// Construction (RFC 9474 §4 Blind): the salt is drawn here, everything
/// else (sample `r` uniform in `[1, n)` by rejection, `inv = r⁻¹ mod n`,
/// the blinding itself) in `blindCore`, shared with `blindWithFactor`.
/// A1 B6/B9: the secrets that survive `blind()` are not copies this module
/// holds. Every `Elem` and byte buffer on the path is `secureZero`'d
/// already; the residue lives in the callees' own temporaries (montint's
/// Montgomery and safegcd scratch; until 2026-11-13 `std.crypto.ff`'s and
/// `std.math.big`'s), which no `secureZero` this module can write reaches. So
/// the stack those callees used is zeroed wholesale instead, the technique
/// `bip340` (F2), `xmss` (F3) and `bulletproofs` (B12) close the same class
/// with.
///
/// Sized when the deepest frame was a 128 KiB big-int Euclid arena
/// (`blind` left 207 632 B of dirty stack); montint's operations need less
/// (`DynModint.stack_bytes`: at most 144 KiB at the 8192-bit capacity). The
/// probe asserts zero residue, so a call tree that outgrows this goes red
/// there.
const blind_stack_burn = 256 * 1024;

/// `blindSign` reaches deeper than `blind`: its CRT private op runs inside
/// `rsa`, and the probe measured 335 424 B of dirty stack below the call
/// where `blind` left 207 632 B (2026-10, both before montint). Measured consequence of getting this
/// wrong: at 256 KiB the key's prime factors `p` and `q` were still readable
/// (2 hits each) below the burn.
const sign_stack_burn = 512 * 1024;

/// Zero `blind_stack_burn` bytes at the depth the blinding computation's
/// frames occupied. `noinline` is load-bearing in the sibling modules that
/// use this pattern: inlined, the buffer lands in the CALLER's frame, above
/// the region the computation used, and the probe finds the secret again.
/// Volatile stores keep the dead store.
noinline fn burnStack(comptime bytes: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns, 2026-10-09). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe, 2026-10-09; `align(16)` on
    // the buffer alone did not stop it). At 16 the frame needs no realignment and
    // the buffer ends at the saved frame pointer.
    const V = @Vector(2, u64);
    var buf: [bytes / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

pub fn blind(
    pk: rsa.PublicKey,
    comptime Hash: type,
    prepared_msg: []const u8,
    salt_len: usize,
    random: std.Random,
    ctx_out: *Context,
    blinded_msg_out: []u8,
) BlindError![]u8 {
    // Runs LAST (defers unwind in reverse), i.e. after every secureZero
    // below has wiped what it owns. See burnStack.
    defer burnStack(blind_stack_burn);
    if (salt_len != 0 and salt_len != Hash.digest_length) return error.InvalidSaltLength;
    var salt_buf: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &salt_buf);
    const salt = salt_buf[0..salt_len];
    random.bytes(salt);

    // Steps 5-6 (sample r ∈ [1, n) uniformly, invert it) run inside
    // blindCore, where m is known: one inversion serves both step 4's
    // coprimality check and step 6 (see blindCore).
    return blindCore(pk, Hash, prepared_msg, salt, .{ .random = random }, ctx_out, blinded_msg_out);
}

/// Deterministic variant of `blind` with a caller-supplied blinding
/// factor `r` (big-endian, must be in `[1, n)`): the seam that makes
/// `blind`'s output reproducible for the RFC 9474 Appendix A KATs
/// (`kat_test.zig` feeds the RFC's own fixed `r` and asserts
/// `blinded_msg`/`ctx.r_inv` byte-exact).
///
/// Production clients should call `blind`: this form takes `r` from the
/// caller, does not burn the stack afterwards, and keeps the PSS salt as a
/// parameter (RFC 9474 §7.4, see `blind`). Since 2026-11-13 its arithmetic
/// is the same constant-time montint path as `blind`'s (until then it ran
/// the variable-time Euclid inverse on `r` unmasked). `r`'s uniformity
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
    // r must OS2IP into [1, n): elemFromBytesBE rejects >= n, isZero rejects
    // 0. Step 6's inverse (which also rejects gcd(r, n) != 1) runs in
    // blindCore.
    var r = pk.n_mont.elemFromBytesBE(r_bytes) catch return error.InvalidBlindingFactor;
    defer wipeElem(&r);
    if (NMont.isZero(&r)) return error.InvalidBlindingFactor;
    return blindCore(pk, Hash, prepared_msg, salt, .{ .fixed = &r }, ctx_out, blinded_msg_out);
}

/// Where `blindCore` gets its blinding factor `r` from.
const BlindingFactor = union(enum) {
    /// `blind`: drawn uniformly from `[1, n)`, redrawn (at most 4 draws in
    /// all) if it is not a unit mod `n`.
    random: std.Random,
    /// `blindWithFactor`: the caller's `r`, already checked to be in
    /// `[1, n)`; a non-unit is `error.InvalidBlindingFactor`.
    fixed: *const Elem,
};

/// RFC 9474 §4 Blind, shared by `blind` and `blindWithFactor`; everything
/// after step 2 runs on `pk.n_mont` (see "composite-modulus arithmetic"
/// above):
/// 1. `encoded_msg = pssEncode(...)` over `em_bits = bits(n) - 1`.
/// 2. `m = OS2IP(encoded_msg)`.
/// 4-6. `r` from `factor`; `t = (m · r)⁻¹ mod n` by the constant-time
///    safegcd inverse. `t` exists iff BOTH `m` and `r` are units, so the one
///    inversion is step 4's `gcd(m, n) == 1` check and step 6's inverse at
///    once: `inv = r⁻¹ = t · m`. Only when it fails is `m` inverted on its
///    own, to tell the two causes apart (`error.InvalidMessageBlinding` for
///    `m`, a redraw or `error.InvalidBlindingFactor` for `r`).
/// 7. `x = RSAVP1(pk, r) = r^e mod n` (`powPublic`: variable-time in the
///    public `e` only).
/// 8. `z = (m · x) mod n`.
/// 9. `blinded_msg = I2OSP(z, modulus_len)`.
fn blindCore(
    pk: rsa.PublicKey,
    comptime Hash: type,
    prepared_msg: []const u8,
    salt: []const u8,
    factor: BlindingFactor,
    ctx_out: *Context,
    blinded_msg_out: []u8,
) BlindError![]u8 {
    const np = &pk.n_mont;
    // The montint modulus's own length (`toBytesBE` below requires it).
    const modulus_bits = np.bits();
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
    var m = np.elemFromBytesBE(em_buf[0..em_len]) catch return error.InvalidMessageBlinding;
    defer wipeElem(&m);

    // Steps 4-6. r, m·r and the inverses are secret (any one of them
    // unblinds blinded_msg); every Elem is wiped on exit, and `blind`'s
    // stack burn takes what montint leaves below.
    var r: Elem = undefined;
    defer wipeElem(&r);
    var t: Elem = undefined;
    defer wipeElem(&t);
    var r_inv: Elem = undefined;
    defer wipeElem(&r_inv);
    const attempts: usize = switch (factor) {
        .random => 4,
        .fixed => 1,
    };
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        // A non-unit r (it shares p or q with n: probability ~2^-1023 for a
        // uniform draw, or evidence n is malformed) is redrawn a bounded
        // number of times, then reported.
        if (attempt == attempts) return error.InvalidBlindingFactor;
        switch (factor) {
            .random => |g| try sampleElem(np, g, &r),
            .fixed => |f| r = f.*,
        }
        t = np.mul(&m, &r);
        if (np.inverse(&t, &r_inv)) break; // r_inv = (m·r)⁻¹ for now
        // m·r is not a unit. Step 4: if m itself is not, abort — the RFC's
        // own "SHOULD abort" (negligible for a well-formed encoding against
        // a real modulus; finding one is factoring n). Else r was the cause.
        if (!np.inverse(&m, &t)) return error.InvalidMessageBlinding;
    }
    r_inv = np.mul(&r_inv, &m); // (m·r)⁻¹·m = r⁻¹

    ctx_out.* = .{
        .prepared_msg = prepared_msg,
        .salt_len = salt.len,
        .modulus_len = modulus_len,
    };
    np.toBytesBE(&r_inv, ctx_out.r_inv[0..modulus_len]);

    // Step 7: x = RSAVP1(pk, r) = r^e mod n. Like r itself, x is SECRET
    // (x would unblind blinded_msg: m = blinded_msg · x⁻¹).
    var e_buf: [max_modulus_len]u8 = undefined;
    var x = np.powPublic(&r, exponentBE(&pk, &e_buf));
    defer wipeElem(&x);

    // Steps 8-9: z = m·x mod n; blinded_msg = I2OSP(z, modulus_len).
    const z = np.mul(&m, &x);
    np.toBytesBE(&z, blinded_msg_out[0..modulus_len]);
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
/// be the public half of `sk` (`error.SigningFailure` otherwise). `random` feeds the
/// RFC 9474 §7.2 hardening below and MUST be cryptographically secure.
///
/// **§7.2 private-op blinding** — `rsa.rsadpCrtBlinded` with
/// `.{ .csprng = random }` (`rsa`'s F2 base blinding; plain `rsa.rsasp1`
/// runs unblinded): a fresh secret unit `b ∈ [1, n)` is drawn per call, the
/// CRT halves run on `m·b^e` instead of `m`, and each half is unblinded by
/// `b⁻¹` — `s = (m·b^e)^d · b⁻¹ = m^d (mod n)` — so the private-key
/// operation never runs on attacker-chosen input directly. The output is
/// bit-identical to the unblinded computation. Until 2026-11-13 this module
/// built the same construction itself, mod `n` on `std.crypto.ff` with a
/// masked big-int Euclid for `b⁻¹`; `rsa` does it in the CRT domain on
/// montint (two half-size constant-time safegcd inverses, interleaved).
/// A generator that can never produce a usable `b` (all zeros, or only
/// values `>= n`) ends in `error.SigningFailure` (`rsa`'s
/// `error.EntropyFailure` after 128 draws) instead of hanging; one that keeps
/// producing a multiple of `p` or `q` — a party who knows the factors — did
/// stop after four draws and now does not.
///
/// Construction (RFC 9474 §4 BlindSign + §7.2):
/// 1. `m = OS2IP(blinded_msg)`, range-checked against `sk.n` (`blinded_msg`
///    must be exactly `modulus_len` bytes and `m < n`) —
///    `error.InvalidBlindedMessage` on failure.
/// 2. `s = RSASP1(sk, m)` via `rsa.rsadpCrtBlinded` (CRT, with the §7.2
///    base blind above; RSASP1 and RSADP are the same primitive).
/// 3. Mandatory self-check: `m' = RSAVP1(pk, s)` via `rsa.rsavp1`; if
///    `m' != m`, return `error.SigningFailure` (fail closed) — NEVER
///    return an unverified `blind_sig` (Boneh-DeMillo-Lipton CRT-fault
///    defense).
/// 4. `blind_sig = I2OSP(s, modulus_len)` — write `s` into `out` and
///    return the written subslice.
pub fn blindSign(
    sk: *const rsa.SecretKey,
    pk: rsa.PublicKey,
    random: std.Random,
    blinded_msg: []const u8,
    out: []u8,
) BlindSignError![]u8 {
    // Same reason as `blind`: the secrets that survive are inside `rsa` and
    // `montint`, not in copies this module holds. Runs last. See burnStack.
    defer burnStack(sign_stack_burn);
    // `pk` must be sk's public half. A caller-passed value, so a checked
    // verdict rather than an assert (a panic in safe builds, silence in
    // ReleaseFast): sweep BRSA-1. The RSAVP1 self-check below would also catch
    // it, but only after the private operation has run.
    if (!pk.n.v.eql(sk.n.v)) return error.SigningFailure;
    const modulus_len = byteLen(sk.n.bits());
    if (out.len < modulus_len) return error.OutputTooSmall;

    // Step 1: OS2IP + range check (length exact here, value < n inside rsa:
    // its `MessageRepresentativeOutOfRange`).
    if (blinded_msg.len != modulus_len) return error.InvalidBlindedMessage;
    var m_bytes = @as([max_modulus_len]u8, @splat(0));
    @memcpy(m_bytes[max_modulus_len - modulus_len ..], blinded_msg);

    // Step 2 (+ §7.2): s = RSASP1(sk, m) under rsa's base blinding. Audit
    // finding B1: `FaultDetected` (rsa's Bellcore/BDL check, audit F3 in
    // `rsa`) is a real, reachable outcome — a CRT fault — and is exactly the
    // event SigningFailure exists for, never `unreachable`.
    const s_bytes = rsa.rsadpCrtBlinded(max_modulus_len, m_bytes, sk, .{ .csprng = random }) catch |err| switch (err) {
        error.MessageRepresentativeOutOfRange => return error.InvalidBlindedMessage,
        error.FaultDetected => return error.SigningFailure,
        // A broken/adversarial `random` never yielded a usable blinding factor.
        error.EntropyFailure => return error.SigningFailure,
    };

    // Step 3: mandatory self-check RSAVP1(pk, s) == m — fail closed. It is
    // independent of rsa's own F3 check: it runs against `pk`, not `sk`, so it
    // also catches a `pk` that is not `sk`'s public half (B3, B18).
    const m_check = rsa.rsavp1(max_modulus_len, s_bytes, pk) catch return error.SigningFailure;
    if (!std.crypto.timing_safe.eql([max_modulus_len]u8, m_check, m_bytes)) {
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
/// 3. `s = (z · ctx.r_inv) mod n` — constant-time montint multiplication
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
    // The length is the montint modulus's own, which `toBytesBE` below
    // requires (it panics on a shorter output).
    const np = &pk.n_mont;
    if (ctx.modulus_len > max_modulus_len or np.byteLen() != ctx.modulus_len)
        return error.InvalidContext;

    // Step 2: z = OS2IP(blind_sig), fail-closed on z >= n. On `pk.n_mont`
    // (montint) like `blind`; `std.crypto.ff` until 2026-11-13.
    const z = np.elemFromBytesBE(blind_sig) catch return error.SignatureVerificationFailed;
    // ctx.r_inv was written by blind/blindWithFactor as a canonical value
    // < n; a corrupted/foreign ctx fails closed here too.
    var r_inv = np.elemFromBytesBE(ctx.r_inv[0..ctx.modulus_len]) catch
        return error.SignatureVerificationFailed;
    defer wipeElem(&r_inv);

    // Steps 3-4: s = z·r⁻¹ mod n; sig = I2OSP(s, modulus_len).
    const sig = out[0..ctx.modulus_len];
    np.toBytesBE(&np.mul(&z, &r_inv), sig);

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
    _ = @import("fuzz_test.zig");
}

test "meta names RFC 9474 and the sibling rsa dep" {
    try std.testing.expect(std.mem.find(u8, meta.model_after, "9474") != null);
    try std.testing.expectEqualStrings("rsa", meta.deps[0]);
}

test "prepareIdentity is a no-op" {
    try std.testing.expectEqualStrings("hello", prepareIdentity("hello"));
}

test "prepareRandomize prepends exactly randomizer_len fresh bytes and preserves msg" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x42)));
    var out: [randomizer_len + 5]u8 = undefined;
    const prepared = try prepareRandomize("hello", csprng.random(), &out);
    try std.testing.expectEqual(@as(usize, randomizer_len + 5), prepared.len);
    try std.testing.expectEqualStrings("hello", prepared[randomizer_len..]);
}

test "prepareRandomize is non-deterministic across calls (fresh prefix each time)" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7)));
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
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x70)));
    const random = csprng.random();

    const draws = 64;
    var seen: [randomizer_len][256]bool = @as([randomizer_len][256]bool, @splat(@as([256]bool, @splat(false))));
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
        pssEncode(std.crypto.hash.sha2.Sha384, "m", &(@as([40]u8, @splat(0))), 16 * 8, &em),
    );
}

// ── private-helper tests (montint inverse, blind's steps 4-6, sampling) ──

const kat = @import("kat_vectors.zig");

/// A small public modulus as an `NMont` (`fromBytesBEPublic` takes any odd
/// value >= 3; the slot is the 256-bit minimum).
fn smallMont(v: u16) !NMont {
    var be: [2]u8 = undefined;
    std.mem.writeInt(u16, &be, v, .big);
    return NMont.fromBytesBEPublic(&be);
}

fn smallElem(v: u64) Elem {
    var e = NMont.zero;
    e[0] = v;
    return e;
}

test "n_mont inverse: hand-checkable small case (7^-1 mod 15 == 13) and a non-unit (5 mod 15)" {
    const m = try smallMont(15);
    var inv: Elem = undefined;
    try std.testing.expect(m.inverse(&smallElem(7), &inv));
    try std.testing.expectEqual(@as(u64, 13), inv[0]);
    try std.testing.expect(!m.inverse(&smallElem(5), &inv));
}

test "n_mont inverse reproduces the RFC 9474 published inv from r (and back) over the real 4096-bit composite n, and rejects a factor of n" {
    const pk = try kat.publicKey();
    const np = &pk.n_mont;
    const r = try np.elemFromBytesBE(&kat.r);
    var inv: Elem = undefined;
    try std.testing.expect(np.inverse(&r, &inv));
    var got: [kat.a1.inv.len]u8 = undefined;
    np.toBytesBE(&inv, &got);
    try std.testing.expectEqualSlices(u8, &kat.a1.inv, &got);
    // Inverse of the inverse round-trips to r (inv is unique in [0, n)).
    var r_back: Elem = undefined;
    try std.testing.expect(np.inverse(&inv, &r_back));
    var got_r: [kat.r.len]u8 = undefined;
    np.toBytesBE(&r_back, &got_r);
    try std.testing.expectEqualSlices(u8, &kat.r, &got_r);
    // gcd(p, n) == p != 1.
    const p_el = try np.elemFromBytesBE(&kat.p);
    try std.testing.expect(!np.inverse(&p_el, &inv));
}

// ── blind steps 4-6: one inversion of m·r, and which of the two failed ────
//
// `blindCore` inverts `t = m·r` once and derives `r⁻¹ = t⁻¹·m`; only when that
// fails does it invert `m` alone, to decide between step 4's
// `InvalidMessageBlinding` and a bad `r`. A real RSA modulus never shows
// either failure (finding one is factoring `n`), so these tests use a modulus
// with a known small factor: `n = 3·p` (`p` the KAT key's 2048-bit prime;
// `PublicKey.fromBytes` checks size and parity, not primality). Then
// `m` is a unit iff `3 ∤ m`, and since 256 ≡ 1 (mod 3) that is the byte sum
// of the encoding mod 3.

fn threeTimesP() [kat.p.len + 1]u8 {
    var out: [kat.p.len + 1]u8 = undefined;
    var carry: u16 = 0;
    var i: usize = kat.p.len;
    while (i > 0) : (i -= 1) {
        const v = @as(u16, kat.p[i - 1]) * 3 + carry;
        out[i] = @truncate(v);
        carry = v >> 8;
    }
    out[0] = @intCast(carry);
    return out;
}

/// A salt for which `pssEncode(msg, salt)` over `pk` is (`want_div3`) or is
/// not a multiple of 3. Deterministic: tries salts 0, 1, 2, … (each is a
/// multiple with probability ~1/3).
fn saltFor(pk: rsa.PublicKey, msg: []const u8, want_div3: bool) ![48]u8 {
    const Sha384 = std.crypto.hash.sha2.Sha384;
    const em_bits = pk.n.bits() - 1;
    var em: [max_modulus_len]u8 = undefined;
    const em_slice = em[0..byteLen(em_bits)];
    var salt: [48]u8 = @splat(0);
    for (0..64) |k| {
        salt[47] = @intCast(k);
        try pssEncode(Sha384, msg, &salt, em_bits, em_slice);
        var sum: usize = 0;
        for (em_slice) |c| sum += c;
        if ((sum % 3 == 0) == want_div3) return salt;
    }
    return error.NoSuchSalt;
}

test "blind steps 4-6: a non-unit m is InvalidMessageBlinding, a non-unit r is InvalidBlindingFactor, and r_inv is r's inverse (n = 3p)" {
    const Sha384 = std.crypto.hash.sha2.Sha384;
    const n3 = threeTimesP();
    const pk = try rsa.PublicKey.fromBytes(&n3, &kat.e);
    const msg = "blindrsa steps 4-6";
    var ctx: Context = undefined;
    var out: [max_modulus_len]u8 = undefined;
    var r_be = @as([n3.len]u8, @splat(0));

    // m divisible by 3, r = 2 a unit: step 4 fails on m.
    const salt_bad_m = try saltFor(pk, msg, true);
    r_be[n3.len - 1] = 2;
    try std.testing.expectError(error.InvalidMessageBlinding, blindWithFactor(pk, Sha384, msg, &salt_bad_m, &r_be, &ctx, &out));

    // m a unit, r = 3 not: the factor is reported, not the message.
    const salt_ok = try saltFor(pk, msg, false);
    r_be[n3.len - 1] = 3;
    try std.testing.expectError(error.InvalidBlindingFactor, blindWithFactor(pk, Sha384, msg, &salt_ok, &r_be, &ctx, &out));

    // m a unit, r = 2: succeeds, and ctx.r_inv is 2⁻¹ mod n = (n + 1) / 2.
    r_be[n3.len - 1] = 2;
    _ = try blindWithFactor(pk, Sha384, msg, &salt_ok, &r_be, &ctx, &out);
    const np = &pk.n_mont;
    const r_inv = try np.elemFromBytesBE(ctx.r_inv[0..ctx.modulus_len]);
    try std.testing.expect(NMont.isOne(&np.mul(&r_inv, &smallElem(2))));
}

/// A `std.Random` that scripts the modulus-length draws (`sampleElem`'s `r`)
/// and counts them; every other draw (the salt) is zeros.
const ScriptedRandom = struct {
    r_len: usize,
    values: []const []const u8,
    draws: usize = 0,

    fn fill(self: *ScriptedRandom, buf: []u8) void {
        @memset(buf, 0);
        if (buf.len != self.r_len) return;
        const v = self.values[@min(self.draws, self.values.len - 1)];
        self.draws += 1;
        @memcpy(buf[buf.len - v.len ..], v);
    }
};

test "blind redraws r after a non-unit draw, and the result is blindWithFactor's for the second draw" {
    const Sha384 = std.crypto.hash.sha2.Sha384;
    const pk = try kat.publicKey();
    // First r draw is `p` (shares a factor with n), the second the RFC's r.
    var scripted = ScriptedRandom{ .r_len = kat.n.len, .values = &.{ &kat.p, &kat.r } };
    const random = std.Random.init(&scripted, ScriptedRandom.fill);
    var ctx: Context = undefined;
    var out: [max_modulus_len]u8 = undefined;
    const blinded = try blind(pk, Sha384, &kat.a1.prepared_msg, Sha384.digest_length, random, &ctx, &out);
    try std.testing.expectEqual(@as(usize, 2), scripted.draws);
    try std.testing.expectEqualSlices(u8, &kat.a1.inv, ctx.r_inv[0..ctx.modulus_len]);

    const zero_salt: [Sha384.digest_length]u8 = @splat(0);
    var ctx2: Context = undefined;
    var out2: [max_modulus_len]u8 = undefined;
    const want = try blindWithFactor(pk, Sha384, &kat.a1.prepared_msg, &zero_salt, &kat.r, &ctx2, &out2);
    try std.testing.expectEqualSlices(u8, want, blinded);
}

test "blind gives up after exactly four non-unit draws" {
    const Sha384 = std.crypto.hash.sha2.Sha384;
    const pk = try kat.publicKey();
    var scripted = ScriptedRandom{ .r_len = kat.n.len, .values = &.{&kat.p} };
    const random = std.Random.init(&scripted, ScriptedRandom.fill);
    var ctx: Context = undefined;
    var out: [max_modulus_len]u8 = undefined;
    try std.testing.expectError(error.InvalidBlindingFactor, blind(pk, Sha384, &kat.a1.prepared_msg, 0, random, &ctx, &out));
    try std.testing.expectEqual(@as(usize, 4), scripted.draws);
}

test "sampleElem: always in [1, n), even for a modulus with few top-byte bits" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x44)));
    const random = csprng.random();
    // 0x0209 = 521 (prime, 10 bits): the top byte carries only 2 usable
    // bits, so an unmasked draw would reject ~87% of the time — exercises
    // the top-byte mask, the rejection loop, and the zero rejection.
    const m = try smallMont(521);
    var e: Elem = undefined;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        try sampleElem(&m, random, &e);
        try std.testing.expect(e[0] >= 1 and e[0] < 521);
        for (e[1..]) |w| try std.testing.expectEqual(@as(u64, 0), w);
    }
}

// ── B2 anchor: sampleElem's UNIFORMITY, not just its range ─────────────────
//
// ⛔⛔ The test above only pins the RANGE. RFC 9474 §4.2 makes uniformity a
// MUST ("The blinding factor r MUST be randomly chosen from a uniform
// distribution"), and SPEC.md's "Uniform sampling of r in [1, n)" section
// explains why "reduce a wide random value mod n" is the wrong shortcut —
// but nothing enforced it. Two audit mutations SURVIVED the range-only
// test, 42/42 green: `m7b` (top-byte mask one bit too narrow, so every draw
// lands in the LOWER HALF `[1, 2^(bits-1))`) and `m6` (drop the `isZero`
// rejection). These two tests close that gap (written for `sampleFe`, the
// `std.crypto.ff` sampler `sampleElem` replaced on 2026-11-13).

test "B2: sampleElem is not biased toward the lower half of the modulus (audit mutation m7b)" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x66)));
    const random = csprng.random();
    // 1021 is prime; bits(1021) == 10 and 2^9 == 512 sits almost exactly at
    // 1021's own midpoint (50.1%) -- deliberately chosen so a real uniform
    // sampler over [1, 1021) puts roughly HALF its draws at >= 512, while a
    // sampler whose top-byte mask is one bit too narrow can NEVER produce a
    // value >= 512 at all: every draw collapses into [1, 512).
    const m = try smallMont(1021);
    const n: usize = 4000;
    var above_half: usize = 0;
    var e: Elem = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try sampleElem(&m, random, &e);
        try std.testing.expect(e[0] >= 1 and e[0] < 1021);
        if (e[0] >= 512) above_half += 1;
    }
    // True uniform expectation is ~50%; a halved-range sampler scores 0%.
    // 30% is a wide margin below the true rate and a wide margin above the
    // mutant's 0% -- not a coin-flip threshold.
    try std.testing.expect(above_half >= n * 3 / 10);
}

test "B2: sampleElem rejects a zero draw and retries rather than returning it (audit mutation m6)" {
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
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x67)));
    var scripted = ZeroThenRandom{ .inner = csprng.random(), .zeros_left = 1 };
    const random = std.Random.init(&scripted, ZeroThenRandom.fill);

    const m = try smallMont(1021);
    var e: Elem = undefined;
    try sampleElem(&m, random, &e);
    // A sampler that skipped the isZero rejection would have returned 0
    // straight from the scripted first (all-zero) draw.
    try std.testing.expect(e[0] >= 1 and e[0] < 1021);
    try std.testing.expectEqual(@as(usize, 0), scripted.zeros_left); // the zero draw WAS consumed
}

test "blind with a generator that never yields a usable r is InvalidBlindingFactor after max_sample_draws, not a hang (sweep BRSA-2)" {
    const Sha384 = std.crypto.hash.sha2.Sha384;
    const pk = try kat.publicKey();
    // Zeros (rejected as r == 0) for every modulus-length draw. Panics past
    // 100_000 draws so that a loop without a bound fails instead of hanging.
    const Zeros = struct {
        draws: usize = 0,
        fn fill(self: *@This(), buf: []u8) void {
            @memset(buf, 0);
            if (buf.len != kat.n.len) return;
            self.draws += 1;
            if (self.draws > 100_000) @panic("sampleElem: unbounded redraw loop");
        }
    };
    var zeros = Zeros{};
    const random = std.Random.init(&zeros, Zeros.fill);
    var ctx: Context = undefined;
    var out: [max_modulus_len]u8 = undefined;
    try std.testing.expectError(error.InvalidBlindingFactor, blind(pk, Sha384, &kat.a1.prepared_msg, 0, random, &ctx, &out));
    try std.testing.expectEqual(@as(usize, max_sample_draws), zeros.draws);
}

// ── B6/B9 anchor: secret Fe values (and the byte buffers already wiped)
// do not survive on the stack after blind() returns ───────────────────────
//
