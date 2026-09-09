// SPDX-License-Identifier: MIT

//! ctgrind_harness — constant-time evidence for two of `bbs.zig`'s four
//! Fable cores, as an actual committed program instead of an unmeasured
//! sentence. Run it through `../../../scripts/ctgrind.sh bbs` (once the
//! coordinator adds the `TARGETS`/`MODES`/`PATTERN`/`LABEL` entries this
//! file's doc comment suggests below — that script REFUSES an unlisted
//! module rather than silently skipping it).
//!
//! NOT wired into `zig build test-bbs` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on. `zig
//! build check-ctgrind` compiles it (a rot guard, no valgrind) once the
//! coordinator's `build.zig` discovery picks this file up by its path
//! existing.
//!
//! ## Is there a pre-existing constant-time claim this is evidence for?
//!
//! **No.** Unlike `bls12_381/SPEC.md`'s Part 4 ("Constant-time choices"),
//! neither `../SPEC.md` nor `../README.md` states a constant-time claim
//! anywhere for `bbs` itself — grepped for "constant-time", "side-channel",
//! "leak", "timing", "branch": the only hits are `bbs.zig`'s own comments
//! about `computeB`/`msmPublic` (quoted below), never a section making a
//! claim the way `bls12_381`, `k256`, or `ct25519` do. This harness is
//! therefore establishing a FIRST measurement, not validating a published
//! one — nothing here should be read as confirming a documented property,
//! and this doc comment does not add one to `SPEC.md`/`README.md` (the
//! task that asked for this harness was explicit: measure, don't invent
//! the claim).
//!
//! The closest thing to a stated posture is `bbs.zig`'s own comment above
//! `msmPublic`/`computeBPublic` (lines ~233-260), quoted here because it is
//! exactly the design reasoning this harness measures:
//!
//! > `computeB` above stays exactly as it was: a sequential per-generator
//! > `scalarMul` loop, and the ONLY path `sign` and `proofGen` use. Those
//! > two callers' `message_scalars` can include UNDISCLOSED credential
//! > attributes ... or a signer's private message content ... `bls12_381`'s
//! > `kzg.g1Msm` (Pippenger bucket MSM) is EXPLICITLY variable-time ... so
//! > using it there would open a timing side channel on exactly the values
//! > this module's own CT posture (audit A6) protects with `bls12_381`'s
//! > constant-time `scalarMul`.
//!
//! i.e. the module's own source asserts that `sign`/`proofGen` deliberately
//! keep the slow, sequential `computeB` specifically so no MESSAGE scalar
//! (secret in either function) ever reaches a variable-time code path. That
//! is a real, checkable claim, and it is the one this harness measures —
//! by tainting exactly the values that comment says must not leak and
//! watching whether the ladder branches on them.
//!
//! ## The two targets
//!
//! * `sign` — the ISSUER's signing key. `keys.SecretKey.fromBytes` parses
//!   cleanly (its own canonicality check is parse-path validation, not
//!   part of the arithmetic under test — same reasoning
//!   `bls12_381/src/ctgrind_harness.zig`'s `secretFr` documents), then the
//!   resulting scalar's memory is marked undefined and driven through
//!   `bbs.sign(allocator, sk, pk, header, messages)` end to end: `e =
//!   hash_to_scalar(sk || domain || msg_1..msg_L, ..)`, `sk_plus_e_inv =
//!   (sk + e)^-1`, and `A = [sk_plus_e_inv]B` (`bbs.zig` lines ~454-478).
//!   `pk` is derived from the SAME key material but from a SEPARATE,
//!   never-tainted parse (real usage: the issuer's public key is
//!   published once and is not itself secret at the point `sign` runs);
//!   `messages`/`header` are ordinary public string literals — this
//!   target's only claim is about the SECRET KEY, per the task brief.
//! * `proofgen` — the two things a BBS proof's whole purpose is to keep
//!   hidden: the holder's UNDISCLOSED messages and the proof's blinding
//!   randomness (`random_scalars`, draft §3.7.1's `r1,r2,r3,m~_j1..m~_jU`).
//!   Setup (never tainted): a real `bbs.sign` call over `L=3` messages
//!   produces a genuinely valid signature, so `Signature.fromBytes`'s
//!   structural checks inside `proofGen` pass and this drives the real
//!   call rather than an early-return error path. The measured call then
//!   re-taints message indices `{1,2}` (the UNDISCLOSED set;
//!   `disclosed_indexes = {0}`) and all 5 `random_scalars`, and drives
//!   `bbs.proofGen(allocator, pk, signature, header, ph, messages,
//!   disclosed_indexes, random_scalars)`. `pk`/`signature`/`header`/`ph`/
//!   the one DISCLOSED message/`disclosed_indexes` are never tainted —
//!   they are genuinely public at every real call site.
//!
//! ## What this does NOT measure
//!
//! `verify`/`proofVerify` are not driven at all — both operate only on
//! values already public to the verifier (`bbs.zig`'s own comment above
//! `msmPublic` makes this claim explicitly for those two functions'
//! `computeB`/`ProofVerifyInit` accumulations), so there is no witness for
//! them to leak and nothing for a taint-propagation harness to check.
//!
//! ## Inherited substrate (read before attributing a context to `bbs`)
//!
//! Both targets are entirely G1-side (`bbs`'s message accumulator `B`/
//! `Abar`/`Bbar`/`T` are G1 points; the public key `W = [sk]BP2` used here
//! is a G2 point but is computed from a NEVER-tainted scalar, in a call
//! this harness makes before any taint is applied) — neither target
//! reaches `g2.zig`/`fp2.zig`, so the pattern below does not name them.
//! What it DOES inherit from `bls12_381`, per the task brief's own
//! warning (confirmed here, not merely assumed):
//!
//! * `fp.zig`/`g1.zig`/`scalar.zig` — every `G1.Jacobian.scalarMul(p, s)`
//!   call (`computeB`'s loop, `Abar_j = [r1]A`, `Bbar_j = [r1]B -
//!   [e]Abar`, `T_j`'s per-undisclosed-generator terms) is
//!   `scalarMulBytes(p, &s.toBytes())` (`g1.zig`) — the tainted scalar's
//!   `toBytes()` call is exactly the `std.crypto.ff` `Uint.toBytes`
//!   overflow check the brief names (`ff.zig:150`), and the ladder itself
//!   runs on `fp.zig`'s hand-rolled field.
//! * `hash_to_curve.zig` — NOT for curve mapping (neither target ever
//!   calls `hashToCurveG1`; generators are derived from a fixed PUBLIC
//!   seed message, never tainted) but for `expandMessageXmd`, which
//!   `ciphersuite.hashToScalar` delegates to. `sign`'s tainted `sk` flows
//!   into `e`'s hash input (`e_input = sk || domain || msg_1..msg_L`,
//!   `bbs.zig` line ~461) and `proofgen`'s tainted undisclosed message
//!   bytes flow into `messagesToScalars`'s per-message `hashToScalar`
//!   call — both land inside this file, not `bbs`'s own.
//! * NOT inherited here: `Fp2.isZero`'s short-circuit (`g2.zig`/`fp2.zig`)
//!   — that substrate is real (round 2/3 measured it on `bls12_381`/
//!   `tlock`/`ibe`) but neither `sign` nor `proofGen` ever multiplies a
//!   secret scalar into `G2`, so it does not apply to this module's rows.
//!
//! ## The two traps (see `ct25519`/`bls12_381`'s harnesses for the same shape)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without
//!    `-fvalgrind` (off by default outside Debug) — a ReleaseFast binary
//!    built without it is a SILENT NO-OP under valgrind. The driver
//!    builds both ways so this is its own measured row, not a false clean.
//! 2. The optimizer could in principle keep a defined copy of a tainted
//!    value around from before `makeMemUndefined` ran. `reloadVolatile`
//!    forces one real byte-by-byte load from freshly-tainted memory
//!    immediately before the call under test, exactly as the sibling
//!    harnesses do (defensive, not demonstrated — same caveat those files
//!    state).
//!
//! ## The propagation proof
//!
//! After the call under test, this harness prints the result through
//! `std.debug.print` (`sig=` for `sign`, `proof=` for `proofgen`), which is
//! NOT constant-time (hex formatting branches on the value). Those
//! contexts are the WITNESS bucket: seeing them nonzero is what proves the
//! taint actually reached somewhere observable, so a zero count inside
//! `bbs`'s own files means "no branch found", not "taint never arrived".
//!
//! ## ReleaseFast only
//!
//! Same reasoning as every other harness in this collection: Debug/
//! ReleaseSafe add overflow-check branches to ordinary `+`/`-`/`*` that
//! have nothing to do with this module's constant-time question and would
//! bury the ladder's real branch structure under noise neither claim is
//! about.

const std = @import("std");
const builtin = @import("builtin");
const bbs_mod = @import("bbs.zig");
const keys = @import("keys.zig");
const cs = @import("ciphersuite.zig");

const Fr = cs.Fr;

/// Deterministic (not comptime-folded) secret material — real runtime
/// memory, so tainting it marks memory the code under test actually
/// reads. Not a KAT — a diagnostic input, not a correctness one.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// Same, additionally domain-separated by a runtime index — for the
/// `proofgen` target's per-message / per-random-scalar draws.
fn secretBytesIndexed(comptime n: usize, comptime domain: []const u8, i: usize) [n]u8 {
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    var idx: [8]u8 = undefined;
    std.mem.writeInt(u64, &idx, @as(u64, @intCast(i)), .little);
    st.update(&idx);
    var out: [n]u8 = undefined;
    st.squeeze(&out);
    return out;
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

/// A `SecretKey` — clean-parse/taint-after (`keys.SecretKey.fromBytes`'s
/// canonicality check is parse-path validation, not the arithmetic under
/// test). `r[0] = 0` makes the draw canonical without a comparison
/// branch: `r`'s top byte is `0x73` (`bls12_381/src/scalar.zig`), so any
/// 32-byte value whose top byte is `0` is unconditionally `< r` — the
/// same trick `bls12_381/src/ctgrind_harness.zig`'s `secretFr` uses.
fn secretSk(comptime domain: []const u8, tainted: bool) !keys.SecretKey {
    var raw = secretBytes(keys.SecretKey.encoded_bytes, domain);
    var r = reloadVolatile(keys.SecretKey.encoded_bytes, &raw);
    r[0] = 0;
    var sk = try keys.SecretKey.fromBytes(r);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&sk));
    return sk;
}

/// An `Fr` scalar (the `proofgen` target's `random_scalars` shape), same
/// clean-parse/taint-after/top-byte-zero trick as `secretSk`.
fn secretFrIndexed(comptime domain: []const u8, i: usize, tainted: bool) !Fr {
    var raw = secretBytesIndexed(Fr.encoded_bytes, domain, i);
    var r = reloadVolatile(Fr.encoded_bytes, &raw);
    r[0] = 0;
    var v = try Fr.fromBytes(r);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&v));
    return v;
}

/// One message's content — real runtime bytes so `makeMemUndefined` marks
/// memory the code under test actually reads. `tainted` gates whether
/// THIS particular message (an undisclosed one) is marked before the
/// final reload; a disclosed message is drawn the same way but always
/// called with `tainted = false`.
fn messageBytes(comptime n: usize, comptime domain: []const u8, i: usize, tainted: bool) [n]u8 {
    var raw = secretBytesIndexed(n, domain, i);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(&raw);
    return reloadVolatile(n, &raw);
}

const msg_len = 24;
/// `L = 3` total messages, `disclosed_indexes = {0}`, undisclosed = `{1,2}`
/// (`U = 2`) — small enough to keep the memcheck run fast while still
/// exercising the per-undisclosed-generator loop in `T`'s accumulation
/// (`bbs.zig` lines ~628-631) with more than one term.
const total_messages = 3;
const disclosed_index: usize = 0;
const random_scalar_count = 3 + (total_messages - 1); // 3 + U

const Target = enum { sign, proofgen };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "sign")) return .sign;
    if (std.mem.eql(u8, s, "proofgen")) return .proofgen;
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

    const allocator = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    const header = "ctgrind-bbs-harness-header-v1";

    switch (target) {
        .sign => {
            // The issuer's own public key, derived from a SEPARATE,
            // NEVER-tainted parse of the same key material — real usage
            // publishes `pk` once, well before/independently of any given
            // `sign` call, so it must not carry the taint under test.
            const pk_sk = try secretSk("ctgrind-bbs-harness-sk-v1", false);
            const pk = keys.skToPk(pk_sk);

            // The tainted issuer signing key entering `sign`.
            const sk = try secretSk("ctgrind-bbs-harness-sk-v1", tainted);

            const messages = [_][]const u8{
                "bbs-ctgrind-issuer-message-0",
                "bbs-ctgrind-issuer-message-1",
                "bbs-ctgrind-issuer-message-2",
            };
            const sig_bytes = try bbs_mod.sign(allocator, sk, pk, header, &messages);

            // Propagation witness: downstream of the tainted sk.
            std.debug.print("sig={x}\n", .{sig_bytes});
        },
        .proofgen => {
            // ── setup: NEVER tainted — produce a genuinely valid signature
            // over `total_messages` messages, so `proofGen`'s internal
            // `Signature.fromBytes` structural check passes and the
            // measured call is the real thing, not an early-return error
            // path. ──────────────────────────────────────────────────────
            const setup_sk = try keys.keyGen("ctgrind-bbs-harness-issuer-key-material-v1!", "", null);
            const pk = keys.skToPk(setup_sk);

            var setup_msgs: [total_messages][msg_len]u8 = undefined;
            for (&setup_msgs, 0..) |*m, i| m.* = secretBytesIndexed(msg_len, "ctgrind-bbs-harness-msg-v1", i);
            var setup_slices: [total_messages][]const u8 = undefined;
            for (&setup_slices, &setup_msgs) |*s, *m| s.* = m;

            const signature = try bbs_mod.sign(allocator, setup_sk, pk, header, &setup_slices);

            // ── the measured call: re-taint the UNDISCLOSED messages
            // ({1,2}) and every `random_scalars` entry (the proof's
            // blinding randomness); the disclosed message (0) and every
            // other input stay public. ──────────────────────────────────
            var run_msgs: [total_messages][msg_len]u8 = undefined;
            for (&run_msgs, 0..) |*m, i| {
                const is_undisclosed = i != disclosed_index;
                m.* = messageBytes(msg_len, "ctgrind-bbs-harness-msg-v1", i, tainted and is_undisclosed);
            }
            var run_slices: [total_messages][]const u8 = undefined;
            for (&run_slices, &run_msgs) |*s, *m| s.* = m;

            var random_scalars: [random_scalar_count]Fr = undefined;
            for (&random_scalars, 0..) |*r, i| {
                r.* = try secretFrIndexed("ctgrind-bbs-harness-random-scalar-v1", i, tainted);
            }

            const disclosed_indexes = [_]usize{disclosed_index};
            const ph = "ctgrind-bbs-harness-presentation-header-v1";

            const proof = try bbs_mod.proofGen(
                allocator,
                pk,
                signature,
                header,
                ph,
                &run_slices,
                &disclosed_indexes,
                &random_scalars,
            );
            defer allocator.free(proof);

            // Propagation witness: downstream of both the undisclosed
            // messages and the random_scalars.
            std.debug.print("proof={x}\n", .{proof});
        },
    }
}

// ── suggested scripts/ctgrind.sh config (coordinator: paste in, do not
// generate mechanically — every existing entry carries hand-written
// reasoning in its own comment; this follows the same shape) ───────────
//
// declare -A TARGETS=(
//     [bbs]="sign proofgen"
// )
// declare -A MODES=(
//     [bbs]="ReleaseFast"
// )
// declare -A PATTERN=(
//     # bbs's own files plus the bls12_381 substrate every G1 `scalarMul`
//     # and every `hash_to_scalar` call bottoms out in — see this file's
//     # module doc comment ("Inherited substrate") for why each is here
//     # and why `g2[.]zig`/`fp2[.]zig` are deliberately NOT.
//     [bbs/sign]='bbs[.]zig|ciphersuite[.]zig|keys[.]zig|fp[.]zig|g1[.]zig|scalar[.]zig|hash_to_curve[.]zig'
//     [bbs/proofgen]='bbs[.]zig|ciphersuite[.]zig|keys[.]zig|fp[.]zig|g1[.]zig|scalar[.]zig|hash_to_curve[.]zig'
// )
// declare -A LABEL=(
//     [bbs/sign]='bbs sign SK+bls12_381 g1/fp/ff'
//     [bbs/proofgen]='bbs proofGen undisclosed msgs+randomness+bls12_381 g1/fp/ff'
// )
