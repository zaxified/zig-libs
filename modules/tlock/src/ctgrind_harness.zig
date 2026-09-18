// SPDX-License-Identifier: MIT

//! ctgrind_harness — empirical evidence for `tlock.zig`'s `fp12Pow`
//! (audit finding "tlock F3", `tlock.zig:230`), the module's own
//! hand-rolled constant-time `Gt` exponentiation — plus, at the task's
//! explicit request, the recipient-private-key path through `decrypt`.
//! Run via `../../../scripts/checks/ctgrind.sh tlock` once the coordinator adds
//! the `TARGETS`/`MODES`/`PATTERN`/`LABEL` entries suggested at the
//! bottom of this file (that script REFUSES an unlisted module). NOT
//! wired into `zig build test-tlock` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on.
//!
//! ## Verifying the lead before building on it
//!
//! A triage pass (`~/CML/20260901-zig-libs-audit/ctgrind-triage-3.md`)
//! reported "`tlock`/`ibe` both hand-roll a constant-time `Gt`
//! exponentiation with careful reasoning but no empirical measurement".
//! Checked directly against this tree: TRUE. `tlock.zig`'s private
//! `fp12Pow` (line 236) is a real, committed 4-bit fixed-window
//! square-and-select-always loop over `Fp12.square`/`.mul`, with a
//! `fp12CtSelect` table scan (never `table[idx]`) exactly as its own doc
//! comment (lines 198-272) describes, and the doc comment cites this
//! exact finding by name ("Audit `tlock` F3 / `ibe` F4", line 230). The
//! same triage file's row on `tlock` ALSO says, in its own "Notes"
//! column: "`decrypt` only takes the ALREADY-PUBLISHED `round_signature`,
//! which is public by the time decrypt can run — fine on its own." That
//! second sentence matters for how the `decrypt` target below is read —
//! see "Target 2" below.
//!
//! `fp12Pow` is `fn`, not `pub fn` — private to `tlock.zig`, and Zig's
//! privacy is per-file, so this sibling harness file cannot call it
//! directly without editing `tlock.zig` (out of scope: the task
//! forbids editing `modules/tlock/src/*.zig`). Both targets below
//! therefore drive it through the REAL public API (`tlock.encrypt`),
//! which is arguably more faithful than a synthetic direct call anyway:
//! it is the exact code path a real caller exercises.
//!
//! ## Target 1: `fp12pow` — the F3 lead itself
//!
//! `tlock.encrypt`'s step 7 computes `gid_r = fp12Pow(Gid, r)` where
//! `r = ciphersuite.h3(sigma, message)`. `Gid` (`= pairing(Qid, p_pub)`)
//! is PUBLIC — a pairing of two public points — so only `sigma` and
//! `message` are tainted here; `p_pub` is the (public) `G2` generator
//! and `round` a fixed public constant, both chosen only to give
//! `encrypt` a valid, self-consistent call, carrying no meaning of
//! their own. `fp12Pow`'s own doc comment states the reasoning this
//! target exists to check empirically: "`r = H3(sigma, M)` is
//! secret-derived (leaking it leaks `sigma`, hence the message), so the
//! exponent must be treated exactly like a secret scalar even though
//! this is 'just' encryption-side randomness" (`tlock.zig:215-218`).
//!
//! Tainting `sigma`/`message` instead of `r` directly also puts
//! `ciphersuite.h3`'s OWN code on the tainted path — its rejection-
//! sampling retry loop (`while (i < 65535) : (i += 1) { ... if
//! (Fr.fromBytes(hashed)) |scalar| return scalar else |_| {} }`,
//! `ciphersuite.zig:230-241`) is a genuine secret-VALUE-dependent loop
//! exit (whether iteration 1's hash happens to be canonical depends on
//! the hash of `sigma`/`message`), not a bug this harness exists to
//! hide — see the report's classification of `ciphersuite.zig` contexts.
//!
//! ## Target 2: `decrypt` — the recipient private key, taken literally
//!
//! Taints `round_signature` (the BF-IBE private key for the round's
//! identity — `tlock.decrypt`'s first argument) and drives it through
//! the ENTIRE decrypt pipeline: `pairing.pairing(round_signature, ct.u)`
//! -> `gtToDrandRepr` (square+mul) -> `ciphersuite.h2`/`h4` (SHA-256) ->
//! the FO-check's `scalarMul` recomputation of `U'` -> the final
//! `std.mem.eql` compare -> (on success) the returned `message`. `ct` is
//! `fixtureCiphertext()` — encrypted, with a fixed local keypair built
//! the same way `kat_test.zig`'s own fuzz `DamageSubject.build()` does,
//! to the SAME identity `secretRoundSignature` is the private key for —
//! so the FO check genuinely ACCEPTS and `decrypt` returns real tainted
//! plaintext (see `fixtureCiphertext`'s doc comment for why an
//! unrelated, always-rejecting `ct` — this file's first draft — leaves
//! this target with no reachable propagation witness at all). Every
//! pipeline step still runs on both the accept and reject path; only the
//! final branch and the return value differ. `decrypt`'s own doc comment
//! confirms the FO compare's OUTCOME is meant to be public: "The check's
//! outcome (accept/reject) is public, so a non-constant-time byte
//! compare is fine here" (`tlock.zig:424-425`) — which is why a nonzero
//! count AT THAT ONE COMPARE is not read as a defect below.
//!
//! **Read this target's zero/nonzero rows against the triage's own
//! caveat, not against a wish for a clean "tlock is constant-time"
//! headline:** `round_signature` is drand's PUBLISHED per-round
//! threshold-BLS signature — by the time any caller has a complete one
//! to hand `decrypt`, it is public information (that publication is the
//! entire timelock premise: nobody can decrypt before the round, because
//! nobody has this value yet). There is no realistic window in which a
//! process holds a genuine, still-secret `round_signature` on a machine
//! an attacker can time-probe. The task's own instructions ask for this
//! value to be tainted as "the recipient's identity-based private key",
//! and it genuinely has a taint PATH all the way through `decrypt` (this
//! is not `bolt8`'s structurally-dead `act1` case — see that module's
//! `TARGETS` comment in `scripts/checks/ctgrind.sh` for the shape this ISN'T),
//! so it is measured here and reported honestly; but a nonzero count
//! inside `pairing.zig` is not evidence of a defect in `tlock`; see
//! "the pairing substrate" below.
//!
//! ## The pairing substrate makes no constant-time claim at all
//!
//! `bls12_381/src/pairing.zig` carries ZERO occurrences of the words
//! "constant-time"/"secret"/"branch" (checked directly against this
//! tree) — unlike `fp.zig`/`g1.zig`/`g2.zig`, which do. `bls12_381`'s own
//! `ctgrind_harness.zig` says why: "Neither `SPEC.md` nor `README.md`
//! makes any constant-time claim about hash-to-curve or the pairing
//! itself — both operate on PUBLIC messages/points at every real call
//! site... so this harness does not taint anything flowing into
//! `hash_to_curve.zig` or `pairing.zig`". `tlock.decrypt`'s
//! `pairing.pairing(round_signature, ct.u)` is, as far as this repo's
//! own audit trail goes, the ONE call site anywhere that feeds pairing a
//! value anyone has ever called "secret" — and per the previous section,
//! even that call site's own module doc comment does not actually rely
//! on it being constant-time (the round signature is public by
//! construction once it exists). So the `decrypt` target is expected,
//! ahead of the run, to show real branches inside `pairing.zig`'s Miller
//! loop / final exponentiation if it has any (a separate, EXISTING
//! property of a module with no such claim) — that would confirm
//! `bls12_381`'s own scope statement, not contradict `tlock`'s.
//!
//! ## Deliberate choices
//!
//! 1. ReleaseFast only, same reasoning as `bls12_381`'s harness: Debug's
//!    self-hosted backend emits `.debug_line` valgrind cannot parse
//!    (`scripts/checks/ctgrind.sh`'s header), and ReleaseSafe's overflow checks
//!    on ordinary arithmetic would bury the ladder's branch structure
//!    under checks unrelated to this claim.
//! 2. `reloadVolatile` (byte arrays) / a volatile round-trip (the `G1`
//!    point) force one real load from freshly-tainted memory immediately
//!    before the call under test, so the optimizer cannot hand the
//!    callee a defined copy that predates `makeMemUndefined` — same
//!    defensive, unproven-but-precedented idiom `ct25519`/`bls12_381`'s
//!    harnesses use (see either for the measurement showing it is
//!    insurance, not an observed requirement, on today's compiler).
//! 3. Hex/error formatting of the result via `std.debug.print` is the
//!    propagation witness (not constant-time on purpose) — see
//!    `scripts/checks/ctgrind.sh`'s `WITNESS` bucket.

const std = @import("std");
const builtin = @import("builtin");
const tlock = @import("root.zig");
const ciphersuite = tlock.ciphersuite;
const bls12_381 = tlock.bls12_381;

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;

/// Deterministic "secret" material, computed at runtime (not folded at
/// comptime) so tainting it marks memory the code under test actually
/// reads. Not a KAT — a diagnostic input, not a correctness one; the
/// fixed seed only keeps repeated runs of the table comparable.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// `sigma`/`message`, `fp12pow` target's tainted inputs. Both are plain
/// `[block_bytes]u8` at `tlock.encrypt`'s API boundary, so no field
/// structure needs preserving the way a `G1.Affine`/`Fp` value does.
fn secretBlock(comptime domain: []const u8, tainted: bool) [ciphersuite.block_bytes]u8 {
    const raw = secretBytes(ciphersuite.block_bytes, domain);
    var v = reloadVolatile(ciphersuite.block_bytes, &raw);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(&v);
    return v;
}

/// `round_signature`, `decrypt` target's tainted input — a valid,
/// `sk`/`round`, the `decrypt` target's fixture-construction constants —
/// a small canonical scalar and a fixed round number used ONLY to derive
/// a mutually-consistent `(p_pub, round_signature, ct)` triple, the exact
/// same role `kat_test.zig`'s own fuzz `DamageSubject.build()` gives an
/// identically-shaped `sk`. Not tainted, not meant to model a real
/// beacon's actual secret share — a convenience for building a FIXTURE
/// the `decrypt` target can actually decrypt successfully (see below for
/// why that matters).
const fixture_round: u64 = 424242;
fn fixtureSk() bls12_381.Fr {
    var sk_bytes = [_]u8{0} ** 32;
    sk_bytes[31] = 0x2b;
    return bls12_381.Fr.fromBytes(sk_bytes) catch unreachable;
}

/// `round_signature`, the `decrypt` target's tainted input — `[sk] *
/// H1(beaconId(fixture_round))`, a valid, on-curve, in-subgroup `G1`
/// point (a real, self-consistent BF-IBE private key for
/// `fixtureCiphertext()`'s identity, computed CLEANLY first — see
/// `secretFp`'s reasoning in `bls12_381`'s own harness for why parsing/
/// deriving clean and tainting the RESULT afterwards, rather than
/// tainting raw input bytes, keeps this module's own key-derivation
/// arithmetic off the tainted path when that is not what is being
/// measured). Round-tripped through a volatile pointer first (forces one
/// real load, defeating a register-cached defined copy spanning the
/// taint boundary — see this file's module doc comment) and then, if
/// `tainted`, marked undefined at the `Fp` limb level so memcheck tracks
/// it from that point on.
fn secretRoundSignature(tainted: bool) g1.Affine {
    const qid = ciphersuite.h1(ciphersuite.beaconId(fixture_round));
    var sig = g1.Jacobian.fromAffine(qid).scalarMul(fixtureSk()).toAffine();
    const vp: *const volatile g1.Affine = &sig;
    sig = vp.*;
    if (tainted) {
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&sig.x.limbs));
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&sig.y.limbs));
    }
    return sig;
}

/// A fixed `Ciphertext` for the `decrypt` target — encrypted to the SAME
/// `fixtureSk()`-derived `p_pub`/`fixture_round` that
/// `secretRoundSignature` answers for, so `decrypt` actually SUCCEEDS and
/// returns a real `message` to print.
///
/// ⚠ This matters for more than tidiness: `decrypt`'s reject path
/// `std.crypto.secureZero`s its scratch `message` before returning
/// `error.FoCheckFailed` (`tlock.zig:434-437`, by design — see that
/// function's doc comment) and the public API returns NOTHING else on
/// that path, so a `ct` that never corresponds to `round_signature` (the
/// first, simpler version of this harness used exactly that — an
/// arbitrary fixed `ct`) gives this target NO reachable tainted output at
/// all: every run rejects, and the only thing printed is a defined error
/// tag. The 8 in-file branches below are still real (they fire before
/// the reject), but there was no independent propagation WITNESS the way
/// `scripts/checks/ctgrind.sh`'s own accounting discipline asks for. Making
/// `decrypt` actually succeed here is what gives this row a witness
/// alongside its in-file count.
fn fixtureCiphertext() tlock.Ciphertext {
    const p_pub = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(fixtureSk()).toAffine();
    const message = [_]u8{0x5a} ** ciphersuite.block_bytes;
    const sigma = [_]u8{0x11} ** ciphersuite.block_bytes;
    return tlock.encrypt(p_pub, fixture_round, message, sigma);
}

const Target = enum { fp12pow, decrypt };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "fp12pow")) return .fp12pow;
    if (std.mem.eql(u8, s, "decrypt")) return .decrypt;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .fp12pow => {
            // p_pub/round are PUBLIC and fixed — the G2 generator stands in for
            // a real master public key, carrying no meaning of its own (see
            // "Target 1" above). Only sigma/message are tainted.
            const p_pub = g2.Affine.generator;
            const round: u64 = 1000;
            const message = secretBlock("ctgrind-tlock-harness-message-v1", tainted);
            const sigma = secretBlock("ctgrind-tlock-harness-sigma-v1", tainted);

            const ct = tlock.encrypt(p_pub, round, message, sigma);
            // Propagation witness: non-constant-time hex formatting of the
            // (tainted, if taint=yes) ciphertext bytes.
            std.debug.print("ct={x}\n", .{ct.toBytes()});
        },
        .decrypt => {
            const round_signature = secretRoundSignature(tainted);
            const ct = fixtureCiphertext();
            if (tlock.decrypt(round_signature, ct)) |message| {
                // The expected outcome: `round_signature` genuinely corresponds
                // to `ct`'s identity (see `fixtureCiphertext`'s doc comment), so
                // the FO check accepts and `message` — real tainted plaintext —
                // is the propagation witness. Non-constant-time hex formatting
                // on purpose (see this file's module doc comment, point 3).
                std.debug.print("message={x}\n", .{message});
            } else |err| {
                // Reachable only if the fixture construction above is ever
                // changed inconsistently; handled so that mistake fails loudly
                // (a defined error tag, not a crash) instead of silently
                // reporting zero witness contexts for the wrong reason.
                std.debug.print("decrypt_error={t}\n", .{err});
            }
        },
    }
}

// ── suggested scripts/checks/ctgrind.sh config (coordinator: paste in, do not
// generate mechanically — every existing entry carries hand-written
// reasoning in its own comment; these follow the same shape) ─────────────
//
// declare -A TARGETS=(
//     [tlock]="fp12pow decrypt"
// )
// declare -A MODES=(
//     [tlock]="ReleaseFast"
// )
// declare -A PATTERN=(
//     # ⚠ MEASURED, not guessed: this is wider than "just fp12Pow" on purpose.
//     # `encrypt`'s step 6 (`U = r*G2gen`, tlock.zig:361) shares the SAME
//     # tainted `r` fp12Pow's step 7 uses, and driving fp12Pow only through the
//     # real public `encrypt` API (it is private — see this harness's module
//     # doc comment) puts step 6 on the tainted path too, whether or not that
//     # was the intent. fp12Pow/fp12CtSelect/gtToDrandRepr (tlock.zig) +
//     # h3's rejection-sampling retry (ciphersuite.zig, genuinely tainted —
//     # Target 1) + the Fp12/Fp6/Fp2/Fp tower fp12Pow's square/mul bottom out
//     # in AND g2/scalar (step 6's scalarMul+toAffine+toBytesCompressed) —
//     # all bls12_381, inherited, attributed here rather than delegated as
//     # "someone else's problem" (same reasoning chachapoly/oscore/bolt8 apply
//     # to their own delegated files). THE MEASUREMENT: zero of the 8 in-file
//     # contexts are inside fp12Pow itself — all 8 are step 6 (g2/fp2, 7
//     # contexts) or h3's retry (ciphersuite.zig/std.crypto.ff, 1 context).
//     # fp12Pow/fp12CtSelect/gtToDrandRepr measure CLEAN. See the harness
//     # report for the full file:line breakdown.
//     [tlock/fp12pow]='tlock[.]zig|ciphersuite[.]zig|fp12[.]zig|fp6[.]zig|fp2[.]zig|fp[.]zig|g2[.]zig|scalar[.]zig'
//     # decrypt's own file plus the pairing it calls with a tainted G1 point,
//     # the Fp12 tower gtToDrandRepr uses, ciphersuite's h3 retry + h2/h4
//     # (SHA-256), and the FO-check's G2 scalarMul+toAffine+toBytesCompressed+
//     # std.mem.eql (round_signature-derived r_check and U').
//     # ⚠ pairing.zig makes NO constant-time claim anywhere in this repo (see
//     # this harness's module doc comment) — the one context inside it
//     # (Fp12.inv in the final exponentiation's easy part) is expected
//     # substrate behavior, not a tlock defect.
//     [tlock/decrypt]='tlock[.]zig|ciphersuite[.]zig|pairing[.]zig|fp12[.]zig|fp6[.]zig|fp2[.]zig|fp[.]zig|g2[.]zig|g1[.]zig|scalar[.]zig|mem[.]zig'
// )
// declare -A LABEL=(
//     [tlock/fp12pow]='tlock encrypt r->fp12Pow (F3, clean)+g2 step6+h3'
//     [tlock/decrypt]='tlock decrypt sk+bls12_381 pairing (no ct claim)'
// )
