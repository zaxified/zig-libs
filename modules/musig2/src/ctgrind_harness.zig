// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Three
//! DISTINCT sign-flips" threat-model section, specifically the nonce parity
//! mask ("a constant-time masked select, never a branch on the parity bit
//! itself, since which nonce got negated is a secret-derived bit that a
//! timing/branch side channel could turn into a nonce-reuse-shaped key
//! leak") and the secret-key negation `d = g·gacc·d'` ("`d'` is SECRET;
//! `Scalar.mul` is constant-time", `root.zig`'s `sign` doc comment, step 4).
//! Run through `zig build ctgrind -Dctgrind-module=musig2
//! -Dctgrind-valgrind=… -Doptimize=ReleaseFast` plus `valgrind
//! --tool=memcheck` by hand — `scripts/checks/ctgrind.sh` has no per-module
//! TARGETS/MODES/PATTERN/LABEL entry for `musig2` yet; the suggested lines
//! are at the bottom of this comment for the coordinator to paste in.
//!
//! NOT wired into `zig build test-musig2` — memcheck's context count is
//! valgrind's own output, not something a Zig test can assert on. `zig
//! build check-ctgrind` compiles it so it cannot rot into an unbuildable
//! recipe.
//!
//! ## Measured 2026-09-09 (ReleaseFast, `-fvalgrind`, `--num-callers=20`)
//!
//! `sign yes` (tainted): 103 contexts. `sign no` (untainted control): 0.
//! `-fvalgrind=false` trap (tainted, no `-fvalgrind`): 0. Every context is
//! attributed (0 unattributed) to one of:
//!
//!   * **81 contexts (79%) are the MANDATORY SELF-VERIFY**, i.e. `sign`'s
//!     final `partialSigVerifyInternal` call (BIP327's fail-closed check on
//!     the partial signature about to be returned) — the SAME finding shape
//!     `bip340`'s own harness records ("63 of 80... came from a MANDATORY
//!     SELF-VERIFY"), here even more pronounced. The self-verify re-derives
//!     the signer's own pubnonce from the tainted `k1'`/`k2'` (`root.zig`
//!     902-903) and feeds it, the just-computed partial signature `s`, and
//!     the pk-derived KeyAgg coefficient `a` into the DELIBERATELY
//!     variable-time `mulPublic`/GLV path (`group.zig`'s `mulPublicGlv`/
//!     `glvCombine`/`wnafDigits`/`splitToSignedHalves`, `scalar.zig`'s
//!     `splitScalar`) — 62 of the 81 — plus point re-parsing
//!     (`cpoint`/`points`/`recoverY`/`sqrt`, 15), coefficient re-derivation
//!     (`keyAggCoeff`, 3) and membership/range re-checks (3). Every one of
//!     these operates on `s`, `R1`/`R2`, or `pk` — values this call is
//!     ABOUT TO DISCLOSE as the partial signature itself — so a variable-time
//!     branch on them discloses nothing the return value doesn't already.
//!   * **17 contexts are `sign`'s OWN pre-self-verify body**: `k1'`/`k2'`
//!     zero+range validation (`root.zig:869-870`+`:310-311`, 4 — same
//!     accepted shape as `bip340`'s own `k'=0` rejection), the
//!     `SecretKeyMismatch`/`PubkeyNotInSession` checks (`:874`/`:875`, 4),
//!     the signer's own KeyAgg coefficient (`:891`, 3), `d_prime`'s
//!     canonicality reparse (`:893`, 1), and **the masked parity-select's
//!     OWN re-validation (`root.zig:887`, 2 contexts — one per nonce)**:
//!     `Scalar.fromBytes` re-checks the byte-selected `sel` against the
//!     scalar field order even though the mask is a single uniform byte
//!     (selects the whole `even` or whole `odd` 32-byte array, never mixes
//!     within one), so the check's OUTCOME never varies — but the
//!     comparison the check runs (`std.crypto.timing_safe.compare`, then a
//!     single post-hoc `if (result != .lt)`) still executes on
//!     secret-derived bytes. Same class as `k256`'s/`bip340`'s own
//!     documented std scalar-canonicality contexts: one decision after a
//!     constant-time primitive, not a per-bit branch.
//!   * **5 contexts are `rejectIdentity`-shaped** (`group.zig:347`'s
//!     `combMulBaseWithTable` guard ×3 — the signer's own pubkey/pubnonce
//!     derivation, `root.zig:872`/`:902`/`:903` — and `group.zig:391`'s
//!     `mulPublicGlv` point-identity guard ×2, inside the self-verify):
//!     the accepted, ~2^-256-probability class this repo's `k256`/`bip340`
//!     harnesses already document.
//!   * **2 contexts are `bip340`-inherited** (`root.zig:131`/`:132`,
//!     `SecretKey.fromBytes`'s canonicality+zero check on the tainted `sk`
//!     — the same call every caller, including `bip340`'s own harness,
//!     makes before invoking either module's `sign`).
//!   * **2 contexts are the propagation witness** (`Io.Writer.printHex`,
//!     via `std.debug.print`).
//!   * `group.zig:187` (`Secp256k1.add`, 6 contexts, folded into the GLV
//!     bucket above) disassembles at the reported addresses to plain `mov`
//!     loads, not a `Jcc`/`cmov` — most likely LLVM's line-table
//!     interleaving attributing a neighbouring branch (in the same
//!     aggressively-inlined `add`+`Fe.mul`+`fieldMulAmd64` block) to `add`'s
//!     entry line, the same kind of inlining artifact `ct25519`'s harness
//!     documents for its own barrier. Not independently resolved; flagged
//!     here rather than silently folded away.
//!
//! Suggested `ctgrind-expected.tsv` claim row: `total>=100`, `in-file=101`
//! (`103 - 2` witness), `unattr=0`.
//!
//! ## The one target: `sign`
//!
//! `sign` (`root.zig`'s top-level `sign`, BIP327 §"Signing") is the
//! module's only entry point that consumes fresh secret material per call
//! (`keyAgg`/`nonceAgg`/`getSessionValues`/`partialSigVerify`/
//! `partialSigAgg`/`applyTweak` all operate on PUBLIC data only — every one
//! of their multiplies is the documented variable-time `mulPublic`, per
//! `bip340.verify`'s own precedent; see `SPEC.md`'s "Design" section and
//! `keyAgg`'s own doc comment).
//!
//! Tainted, right before the call: the 32-byte BIP340 `SecretKey` `d'` and
//! the two 32-byte secret nonce scalars `k1'`/`k2'` inside the `SecNonce`
//! (BIP327's "per-signature secret nonce pair" — MuSig2's headline
//! departure from single-signer Schnorr is exactly that there are two of
//! these, not one). That taint reaches, end to end: the constant-time
//! masked parity select over `k1'`/`k2'` (step 1), the coefficient
//! multiply `e·a·d` and the negation `d = g·gacc·d'` (steps 2-4), the final
//! scalar `s = k1 + b·k2 + e·a·d` (step 5), the two `combMulBase` calls
//! that rebuild the signer's own pubnonce for the mandatory self-verify
//! (step 6), and the self-verify equation itself (step 7).
//!
//! NOT tainted: `SecNonce.pubkeyBytes()` (the signer's own already-known
//! plain pubkey, copied in unchanged — the caller possesses it before the
//! session starts, it is not part of the "per-signature secret" the task
//! scoped), the co-signer's pubkey, the aggregate public key `Q`, the
//! message, and both signers' published `PubNonce`/`AggNonce` bytes. All of
//! these are computed from CLEAN (untainted) local copies before the
//! tainted copies are made — see "Two clean phases, then one tainted call"
//! below — so a context attributed to `keyAgg`/`nonceAgg`/`getSessionValues`
//! cannot be an artifact of a taint that leaked in from the wrong place.
//!
//! ## Two clean phases, then one tainted call
//!
//! 1. **Keygen/noncegen phase (clean):** `sk_a`'s 32 bytes and `k1'`/`k2'`'s
//!    32 bytes each are drawn deterministically, and IMMEDIATELY used —
//!    before any `makeMemUndefined` call touches them — to compute the
//!    signer's own plain pubkey (`combMulBase(sk_a) -> cbytes`) and its own
//!    `PubNonce` (`combMulBase(k1'), combMulBase(k2') -> cbytes`). A second,
//!    entirely public signer B is built from a fixed public scalar (never
//!    tainted, ever) so the session is a genuine 2-of-2 rather than a
//!    trivial n=1 aggregate. `keyAgg`/`nonceAgg`/`SessionContext` are built
//!    from these clean bytes — this is the "already published, before this
//!    signature" material a real co-signer already holds.
//! 2. **The tainted call:** fresh copies of `sk_a`'s bytes and of ONLY the
//!    `k1'`/`k2'` half of the `SecNonce` (bytes 0..64; the trailing pubkey
//!    bytes 64..97 are the clean, already-public copy from phase 1, never
//!    marked undefined) are conditionally `makeMemUndefined`'d, reloaded
//!    through a volatile pointer (trap 2 below), and passed into `sign`.
//!
//! This mirrors `k256`'s `sign` target (which taints the raw secret key and
//! lets `bip340Sign` derive the public key from it) EXCEPT that `sign`
//! here also needs a `SessionContext` (a multi-party aggregate + aggnonce)
//! to exist beforehand — MuSig2 is not single-signer — so "before the
//! session" material has to be constructed from a clean copy rather than
//! simply not existing yet.
//!
//! ## musig2-own vs k256/bip340-inherited
//!
//! `sign`'s call graph re-enters `bip340`'s tagged-hash helpers
//! (`bip340.hash.taggedHasher`, reached via this module's own
//! `reduceToScalar`/`keyAggCoeff`/`getSessionValues`) and `k256`'s group law
//! twice with the tainted material: `combMulBase(sk.bytes)` (the
//! `SecretKeyMismatch` pubkey re-derivation) and, at the end, TWICE more
//! rebuilding the signer's own pubnonce from the unnegated `k1'`/`k2'` for
//! the mandatory self-verify. `k256`'s own `comb` target already measures
//! exactly that function with a tainted scalar
//! (`modules/k256/src/ctgrind_harness.zig`, `group.zig:346`'s
//! `rejectIdentity` context) — attributing this module's own calls into it
//! to "k256's problem" would be the evasion `scripts/checks/ctgrind.sh`'s header
//! exists to refuse (same reasoning as `bip340/sign`'s pattern, which this
//! harness's PATTERN copies almost verbatim since the call graph is a
//! superset of bip340's). The per-line breakdown in the audit record marks
//! each context musig2-own, bip340-inherited, or k256/std-inherited.
//!
//! ⚠ `root[.]zig` is a THREE-WAY basename collision here (musig2's own
//! `root.zig`, `bip340`'s `root.zig`, and `k256`'s `root.zig` — the same
//! trap `blindrsa/rsp`'s harness documents for its own two `root.zig`
//! files). `k256`'s `root.zig` is a thin re-export module with no function
//! bodies of its own reached from this call graph (checked against its
//! source: it only aliases `group.Secp256k1`/`field.Fe`/`scalar.Scalar`),
//! so in practice a `root[.]zig` frame here is either musig2's or bip340's
//! — disambiguated, when it matters, by valgrind's QUALIFIED symbol name
//! (`root.sign`/`root.getSessionValues`/`root.keyAggCoeff*` vs
//! `bip340.sign`/`bip340.taggedHash*`), not by the file name alone.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default
//!    outside Debug. Built WITHOUT `-fvalgrind`, every client request
//!    compiles to nothing and `--taint=yes` silently behaves like
//!    `--taint=no` — measured as its own row below, not assumed.
//! 2. An optimizer is in principle free to keep a defined copy of the
//!    tainted bytes in a register rather than reading back the memory
//!    `makeMemUndefined` marked. `reloadVolatile` forces one real load from
//!    freshly-tainted memory immediately before the call under test.
//!    Defensive, not demonstrated on this host/compiler.
//! 3. ReleaseFast only — `Debug`/`ReleaseSafe` add overflow checks in the
//!    field/scalar arithmetic underneath (`k256`'s `field.zig`/`scalar.zig`)
//!    that branch on tainted values and bury the signal, and Debug's
//!    self-hosted backend is not readable by valgrind's DWARF parser at all
//!    (`scripts/checks/ctgrind.sh` § MODES).
//!
//! ## The propagation witness
//!
//! The result (the 32-byte partial signature) is formatted with
//! `std.debug.print`, which is not constant-time, so a tainted byte
//! reaching it always produces contexts of its own. A non-zero total next
//! to a small, itemised in-file count is what makes the itemisation mean
//! "no branch found" rather than "the harness never ran".
//!
//! ## Suggested config lines for scripts/checks/ctgrind.sh (coordinator to paste in)
//!
//! ```
//! TARGETS[musig2]="sign"
//! MODES[musig2]="ReleaseFast"
//! PATTERN[musig2/sign]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
//! LABEL[musig2/sign]='musig2 sign (d,k1,k2)+bip340+k256+std'
//! ```

const std = @import("std");
const builtin = @import("builtin");
const musig2 = @import("root.zig");
const bip340 = @import("bip340");
const k256 = @import("k256");
const Secp256k1 = k256.Secp256k1;

/// Deterministic "random" material, one Shake256 squeeze per domain string
/// so every value used below is independent. Computed at runtime (not
/// folded at comptime) so tainting a copy of it actually marks memory the
/// signing path reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// A scalar comfortably inside `[1, n)`: clearing the top (big-endian, per
/// this module's `Scalar.fromBytes(_, .big)` convention throughout)
/// byte keeps the value below the secp256k1 group order, and forcing the
/// last byte non-zero avoids the all-zero edge — both `SecNonce.k1Scalar`/
/// `k2Scalar` and `bip340.SecretKey.fromBytes` reject a zero scalar.
fn secretScalar(comptime domain: []const u8) [32]u8 {
    var s = secretBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the code under test cannot be fed a copy that predates
/// `makeMemUndefined` — see trap 2 above.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { sign };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "sign")) return .sign;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;
    _ = target; // only one target exists today; kept for parity with every other harness's CLI shape

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    // ── Phase 1: keygen/noncegen — entirely CLEAN, never tainted ─────────
    //
    // Signer A is the one whose `sign` call is under test; signer B is a
    // second, purely public participant (fixed scalar, its "secret" is
    // never drawn from anywhere sensitive and never passed through
    // `taintIf`) so the session is a genuine 2-of-2 aggregate rather than a
    // trivial single-key one.
    const sk_a_bytes = secretScalar("musig2-ctgrind-sk-a-v1");
    const pk_a_point = Secp256k1.combMulBase(sk_a_bytes, .big) catch return error.KeygenFailed;
    const pk_a_bytes = Secp256k1.toCompressedSec1(pk_a_point);
    const pk_a = musig2.PlainPublicKey.fromBytes(pk_a_bytes) catch return error.KeygenFailed;

    const sk_b_bytes = secretScalar("musig2-ctgrind-PUBLIC-sk-b-v1"); // public co-signer, never tainted
    const pk_b_point = Secp256k1.combMulBase(sk_b_bytes, .big) catch return error.KeygenFailed;
    const pk_b_bytes = Secp256k1.toCompressedSec1(pk_b_point);
    const pk_b = musig2.PlainPublicKey.fromBytes(pk_b_bytes) catch return error.KeygenFailed;

    const k1_prime_bytes = secretScalar("musig2-ctgrind-k1-a-v1");
    const k2_prime_bytes = secretScalar("musig2-ctgrind-k2-a-v1");
    const r1_a = Secp256k1.combMulBase(k1_prime_bytes, .big) catch return error.NoncegenFailed;
    const r2_a = Secp256k1.combMulBase(k2_prime_bytes, .big) catch return error.NoncegenFailed;
    var pubnonce_a_bytes: [66]u8 = undefined;
    pubnonce_a_bytes[0..33].* = Secp256k1.toCompressedSec1(r1_a);
    pubnonce_a_bytes[33..66].* = Secp256k1.toCompressedSec1(r2_a);
    const pubnonce_a = musig2.PubNonce.fromBytes(pubnonce_a_bytes) catch return error.NoncegenFailed;

    // Signer B's published nonce pair — public, drawn from fixed public
    // scalars, never tainted.
    const kb1_bytes = secretScalar("musig2-ctgrind-PUBLIC-k1-b-v1");
    const kb2_bytes = secretScalar("musig2-ctgrind-PUBLIC-k2-b-v1");
    const r1_b = Secp256k1.combMulBase(kb1_bytes, .big) catch return error.NoncegenFailed;
    const r2_b = Secp256k1.combMulBase(kb2_bytes, .big) catch return error.NoncegenFailed;
    var pubnonce_b_bytes: [66]u8 = undefined;
    pubnonce_b_bytes[0..33].* = Secp256k1.toCompressedSec1(r1_b);
    pubnonce_b_bytes[33..66].* = Secp256k1.toCompressedSec1(r2_b);
    const pubnonce_b = musig2.PubNonce.fromBytes(pubnonce_b_bytes) catch return error.NoncegenFailed;

    const aggnonce = musig2.nonceAgg(&.{ pubnonce_a, pubnonce_b }) catch return error.NonceAggFailed;

    const msg = "musig2 ctgrind harness message"; // PUBLIC by BIP327 (the verifier has it)
    const pubkeys = [_]musig2.PlainPublicKey{ pk_a, pk_b };
    const ctx = musig2.SessionContext{
        .aggnonce = aggnonce,
        .pubkeys = &pubkeys,
        .tweaks = &.{}, // untweaked session: keeps the measured call graph to Sign's own core
        .msg = msg,
    };

    // ── Phase 2: the tainted call ──────────────────────────────────────
    //
    // Fresh copies of the secret key and of ONLY the k1'/k2' half of the
    // secnonce are conditionally marked undefined; the trailing pubkey
    // bytes (already public, from phase 1) are copied in clean.
    var sk_copy = sk_a_bytes;
    taintIf(tainted, &sk_copy);
    const sk_reloaded = reloadVolatile(32, &sk_copy);
    const sk = bip340.SecretKey.fromBytes(sk_reloaded) catch return error.BadSecretKey;

    var secnonce_bytes: [97]u8 = undefined;
    secnonce_bytes[0..32].* = k1_prime_bytes;
    secnonce_bytes[32..64].* = k2_prime_bytes;
    secnonce_bytes[64..97].* = pk_a_bytes; // clean: the signer's own already-public key
    taintIf(tainted, secnonce_bytes[0..64]);
    const secnonce_reloaded = reloadVolatile(97, &secnonce_bytes);
    const secnonce = musig2.SecNonce.fromBytes(secnonce_reloaded);

    // The call under test.
    const psig = musig2.sign(secnonce, sk, ctx) catch |err| {
        std.debug.print("sign failed: {t}\n", .{err});
        return err;
    };

    // Propagation witness: format the (tainted, if taint=yes) result through
    // a non-constant-time path. See the module doc comment above.
    std.debug.print("psig={x}\n", .{psig.bytes});
}
