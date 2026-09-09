// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Threat
//! model" § "Signing-share secrecy" claim: "`Secp256k1.scalar`'s field ops
//! are std's own constant-time implementation; this module introduces no
//! additional branches on secret scalars in its REAL code." That sentence
//! had no measurement behind it before this file — this closes that gap the
//! same way `modules/k256/src/ctgrind_harness.zig` (this module's curve
//! dependency, already measured) and `modules/ct25519/src/ctgrind_harness.zig`
//! (canonical shape for this file) do for theirs.
//!
//! Run via `zig build ctgrind -Dctgrind-module=frost -Dctgrind-valgrind=<bool>
//! -Doptimize=ReleaseFast` (the shared `scripts/ctgrind.sh` has no per-module
//! recipe for `frost` yet — see its header for the manual valgrind
//! invocation). NOT wired into `zig build test-frost`: memcheck's context
//! count is valgrind's own verdict, not something a Zig test can assert on.
//! `zig build check-ctgrind` compiles this file (module-graph auto-discovers
//! it from its own existence — see `build.zig`'s `ctgrindHarnesses`) so it
//! cannot rot into an unbuildable recipe.
//!
//! ## The two targets
//!
//! * `commit` — `round1Commit(nonces)` (`root.zig:921`), the public half of
//!   RFC 9591 §5.1 `commit`, with BOTH of `nonces.hiding`/`nonces.binding`
//!   tainted. This is two `Secp256k1.combMulBase` calls
//!   (`root.zig:930`/`:932`) — the exact ladder `k256/comb` already
//!   measures, driven here from `frost`'s own call site instead of
//!   `k256`'s harness's synthetic scalar.
//! * `sign` — `round2Sign(allocator, identifier, signing_share,
//!   group_public_key, nonces, msg, commitment_list)` (`root.zig:983`), RFC
//!   9591 §5.2 `sign` — THE signing round the task brief names. Tainted:
//!   `signing_share` (the Shamir share `sk_i`) AND `nonces` (the same
//!   per-signature hiding/binding pair as `commit`, independently
//!   generated). This exercises the full signature-share equation at
//!   `root.zig:1018-1020`: `sig_share = hiding + binding*binding_factor +
//!   lambda_i*sk_i*challenge` — every operand that touches `nonces`/
//!   `signing_share` is a `Secp256k1.scalar` field op (`.add`/`.mul`), same
//!   as `k256/sign`'s BIP340 nonce/key arithmetic.
//!
//! **What is deliberately NEVER tainted**, per the task brief: `identifier`
//! (public participant index), `group_public_key`, `msg`, and every entry of
//! `commitment_list` (including the harness's own participant's published
//! hiding/binding commitments). These are constructed from INDEPENDENT
//! scalars that are never passed through `taintIf` at all — not "tainted
//! then declassified", just never marked, so there is no taint to leak into
//! `computeBindingFactors`/`computeGroupCommitment`/`computeChallenge`
//! (`round2Sign`'s first four sub-steps, all public-only per RFC 9591 §4.4-
//! §4.6) in the first place. This is deliberate decoupling: a real signer's
//! own published commitment is DERIVED from the same nonce pair it later
//! feeds to `round2Sign`, but reusing `commit`'s tainted output here would
//! make `binding_factor`/`group_commitment`/`challenge` carry taint too
//! (memcheck tracks byte provenance, not "this became public once
//! serialized"), contaminating `sign`'s in-file count with contexts that
//! are really `commit`'s own combMulBase ladder re-counted under a
//! different name. `round2Sign` does not itself check that its
//! `nonces`/`signing_share` correspond to the `identifier` whose entry sits
//! in `commitment_list` (`root.zig:971-977`'s own doc comment says this is
//! the caller's job), so a `commitment_list` built from unrelated public
//! material still exercises every real branch `sign` has.
//!
//! ## Own code vs. the `k256` delegate
//!
//! Every secret-touching operation in both targets is either (a) frost's
//! own scalar-field glue (`root.zig`'s `.add`/`.mul`/`.invert` calls,
//! `Secp256k1.scalar`'s std-supplied constant-time ops) or (b)
//! `k256`'s `combMulBase`/`combMulBaseWithTable` (`group.zig`) plus the
//! `field.zig`/`fast_core.zig` arithmetic underneath it. `frost` has NO
//! elliptic-curve code of its own — every point operation delegates to
//! `k256` — so `PATTERN` below names both `root.zig` (frost's own scalar
//! glue) and k256's `group.zig`/`field.zig`/`fast_core.zig` (the ladder),
//! the same reason `bolt8`'s and `chachapoly`'s patterns name their
//! delegates instead of attributing only to the calling module's own file.
//! ⚠ `root[.]zig` is frost's OWN basename but is shared with several other
//! modules in this tree (`bip340`, `k256`, `blindrsa`, `rsa`, …) — see
//! `scripts/ctgrind.sh`'s `blindrsa` comment for the exact trap. It is a
//! live risk here only in principle: `round1Commit`/`round2Sign` never call
//! into `bip340` (the module doc comment: "no function in this module
//! currently calls into bip340"), so no `bip340/root.zig` frame should ever
//! appear in either target's stack — but the coordinator should re-verify
//! this by qualified symbol name (`root.round1Commit` vs `root.blindSign`
//! vs `root.something_bip340`), not by trusting the regex, exactly as the
//! `blindrsa` note requires.
//!
//! `k256`'s own `mul`/`combMulBase` end in `try q.rejectIdentity()`/`try
//! acc.rejectIdentity()` (`modules/k256/src/group.zig:278`, `:347`) — "did
//! the ladder land on the identity", probability ≈2^-256, a known accepted
//! class per `k256`'s own harness doc comment, NOT a new defect. Expect
//! `commit` to show exactly this shape twice (once per `combMulBase` call)
//! and `sign` zero times more (round2Sign's own point arithmetic —
//! `computeGroupCommitment`'s `binding.mul`/`.add` — runs on PUBLIC
//! commitment-list material in this harness's construction, so it should
//! contribute no additional tainted-ladder contexts at all; if it does,
//! that is itself a finding, not expected).
//!
//! ## The two traps (see `ct25519`/`k256`'s harnesses for the same shape)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default
//!    outside Debug. A ReleaseFast binary built WITHOUT `-fvalgrind` is a
//!    SILENT NO-OP: `makeMemUndefined` never fires and every row reads zero
//!    regardless of what the code does. Build both ways; the no-`-fvalgrind`
//!    row is the trap control.
//! 2. `reloadVolatile` forces one real load from freshly-tainted memory
//!    through a volatile pointer immediately before the value is consumed,
//!    so the optimizer cannot feed the ladder/field-op chain a
//!    still-defined register copy from before `makeMemUndefined` ran.
//!    Defensive, not independently demonstrated for THIS harness (see
//!    `ct25519`'s harness for the one measured case where removing it made
//!    no observed difference on zig 0.16.0/x86_64/ReleaseFast).
//! 3. ⛔⛔ ReleaseFast ONLY. Built at Debug or ReleaseSafe, std's checked
//!    integer arithmetic inside the `u256`/`u512` limb code
//!    (`k256/field.zig`) branches on the tainted limbs directly and floods
//!    the report with tens of thousands of meaningless overflow-check
//!    contexts — the exact trap this module's task brief calls out by name.
//!
//! ## Scalar construction: routed through frost's OWN real functions
//!
//! Earlier drafts of this harness built the tainted `Scalar`s in a private
//! helper here (calling `Scalar.fromBytes48` directly from
//! `ctgrind_harness.zig`) — measured, that put `ctgrind_harness.zig` itself
//! on the stack instead of any `frost`/`k256` file, so every canonicality
//! check landed in `unattr` even though the branch is real: a HARNESS
//! ARTIFACT (wrong attribution), not a false claim about the branch
//! itself. Fixed by routing every tainted value through this module's own
//! real entry points instead of reimplementing their arithmetic:
//! `SigningShare.fromBytes` (`root.zig:509`, real wire-deserialization —
//! what a participant actually calls on a share it received) for the
//! signing share, and `generateNonces` (`root.zig:370`, which is real,
//! non-stubbed code — two `nonceGenerate`/`h3`/`hashToScalar`/
//! `expandMessageXmd48` calls) for the nonce pair, seeded from the SAME
//! `SigningShare` (RFC 9591's "hedged" construction: nonce_generate takes
//! the participant's own secret precisely so a bad RNG alone cannot break
//! it — §4.1's opening paragraph). Both are frost's real production call
//! graph for exactly this data, not a shortcut invented for measurement,
//! and both leave a `root.zig` frame on every stack so `PATTERN` attributes
//! correctly instead of losing the context to `unattr`.
//!
//! `SigningShare.fromBytes`'s canonical-range check
//! (`Scalar.fromBytes`->`crypto/pcurves/common.zig:75`) and
//! `hashToScalar`'s wide-reduction (`Scalar.fromBytes48`, same underlying
//! `common.zig:75` check on the reduced value) are the SAME std canonicity
//! branch `k256/sign`'s harness already documents ("five at std's
//! scalar-field canonicality check … reached through scalar.zig") — a
//! known, accepted class shared by every module in this tree that turns
//! secret bytes into a `Scalar`, not something new to frost.
//!
//! ## The propagation witness
//!
//! Both targets print their tainted result through `std.debug.print`,
//! which is NOT constant-time (digit/hex formatting branches on the value).
//! A non-zero total next to a small itemised in-file count is what makes a
//! zero in-file count mean "no branch found" rather than "the taint never
//! arrived" — see `WITNESS` in `scripts/ctgrind.sh`.
//!
//! ## Suggested `scripts/ctgrind.sh` config (coordinator wires these; NOT
//! added here per this task's own instructions)
//!
//! ```text
//! TARGETS[frost]="commit sign"
//! MODES[frost]="ReleaseFast"
//! PATTERN[frost/commit]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
//! PATTERN[frost/sign]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
//! LABEL[frost/commit]='frost round1Commit (nonce pair)+k256'
//! LABEL[frost/sign]='frost round2Sign (share+nonces)+k256'
//! ```

const std = @import("std");
const builtin = @import("builtin");
const frost = @import("root.zig");
const Secp256k1 = frost.Secp256k1;

/// `n` deterministic bytes from a domain string. Computed at runtime (not
/// folded at comptime) so tainting it actually marks memory the code under
/// test reads.
fn rawBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time — see trap 2 above.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// Tainted (if `tainted`) 32-byte `SigningShare` wire bytes, top byte
/// masked to 0 so the value is trivially canonical (< 2^248 < group order)
/// regardless of taint — the mask is a concrete write that happens BEFORE
/// tainting, same order `k256`'s own harness uses, so it fixes the real
/// runtime value without affecting valgrind's undefined-shadow tracking.
/// Constructed via `SigningShare.fromBytes` (`root.zig:509`) — REAL
/// wire-deserialization code, not a harness-private reimplementation — see
/// the module doc comment's "Scalar construction" section for why this
/// matters for attribution.
fn taintedShare(comptime domain: []const u8, tainted: bool) frost.SigningShare {
    var raw = rawBytes(32, domain);
    raw[0] = 0; // big-endian top byte
    taintIf(tainted, &raw);
    const r = reloadVolatile(32, &raw);
    return frost.SigningShare.fromBytes(r) catch unreachable;
}

/// Tainted (if `tainted`) 32 bytes of fresh randomness for
/// `generateNonces`'s `hiding_random`/`binding_random` parameters.
fn taintedRandom32(comptime domain: []const u8, tainted: bool) [32]u8 {
    var raw = rawBytes(32, domain);
    taintIf(tainted, &raw);
    return reloadVolatile(32, &raw);
}

/// A PUBLIC scalar — NEVER tainted regardless of the harness's `--taint`
/// argument — used for every value the task brief says must stay public
/// (`group_public_key`, `commitment_list` entries). Kept as a distinct
/// function (rather than a `tainted: bool` parameter) so a call site cannot
/// accidentally flip one bit and taint something that must not be.
fn publicScalar(comptime domain: []const u8) frost.Scalar {
    return frost.Scalar.fromBytes48(rawBytes(48, domain), .big);
}

/// A PUBLIC group element `s·G` for a never-tainted scalar — used to build
/// `group_public_key` and the `commitment_list` entries for the `sign`
/// target. `catch unreachable`: the domain-separated scalar is fixed and
/// known not to reduce to zero (mirrors `ct25519`/`k256`'s harnesses'
/// treatment of their own fixed seeds).
fn publicElement(comptime domain: []const u8) frost.Element {
    const p = Secp256k1.combMulBase(publicScalar(domain).toBytes(.big), .big) catch
        unreachable;
    return frost.Element.fromPoint(p) catch unreachable;
}

const Target = enum { commit, sign };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "commit")) return .commit;
    if (std.mem.eql(u8, s, "sign")) return .sign;
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
        .commit => {
            // RFC 9591 §5.1 commit's real two-step shape: SECRET signing
            // share + fresh randomness -> generateNonces (REAL: nonceGenerate
            // x2, root.zig:370) -> the SECRET nonce pair -> round1Commit
            // (root.zig:550-566's own doc comment on SigningNonces — "MUST
            // NOT be shared"). The share is used only to seed the nonces
            // here, exactly as a real `commit` caller would.
            const signing_share = taintedShare("ctgrind-frost-harness-commit-share-v1", tainted);
            const hiding_random = taintedRandom32("ctgrind-frost-harness-commit-hiding-random-v1", tainted);
            const binding_random = taintedRandom32("ctgrind-frost-harness-commit-binding-random-v1", tainted);
            const nonces = frost.generateNonces(signing_share, hiding_random, binding_random);

            const pair = try frost.round1Commit(nonces);

            // Propagation witness: format the (tainted, if taint=yes)
            // public commitments through a non-constant-time path.
            std.debug.print("hiding_comm={x}\n", .{pair.hiding.toBytes()});
            std.debug.print("binding_comm={x}\n", .{pair.binding.toBytes()});
        },
        .sign => {
            // The one participant this harness plays, RFC 9591 §3.1
            // NonZeroScalar convention — PUBLIC by construction (an
            // ordinary small integer), never tainted.
            const identifier = frost.Identifier.fromU16(1) catch unreachable;

            // SECRET: the Shamir signing share, reused for BOTH purposes a
            // real signer uses it for in one round trip -- seeding
            // generateNonces's hedged construction (RFC 9591 §4.1's own
            // rationale: mixing the secret into the nonce derivation
            // defends against a weak RNG alone) AND round2Sign's own
            // signature-share equation below.
            const signing_share = taintedShare("ctgrind-frost-harness-sign-share-v1", tainted);
            const hiding_random = taintedRandom32("ctgrind-frost-harness-sign-hiding-random-v1", tainted);
            const binding_random = taintedRandom32("ctgrind-frost-harness-sign-binding-random-v1", tainted);
            const nonces = frost.generateNonces(signing_share, hiding_random, binding_random);

            // PUBLIC group info + a one-entry commitment list, built from
            // material that is NEVER tainted and NEVER derived from
            // `signing_share`/`nonces` above — see the module doc comment's
            // "own code vs. the k256 delegate" / decoupling rationale.
            // A one-participant commitment list makes
            // `deriveInterpolatingValue`'s lambda_i trivially 1 (RFC 9591
            // §4.2: the loop over `participant_list \ {x_i}` is empty),
            // which is a legitimate degenerate case (Appendix B's t=1),
            // not a shortcut around any branch `round2Sign` itself takes —
            // `commitment_list.len` never gates a branch in `round2Sign`'s
            // own code.
            const group_public_key: frost.GroupPublicKey = publicElement("ctgrind-frost-harness-group-pk-v1");
            var commitment_list = [_]frost.SigningCommitments{.{
                .identifier = identifier,
                .hiding = publicElement("ctgrind-frost-harness-list-hiding-v1"),
                .binding = publicElement("ctgrind-frost-harness-list-binding-v1"),
            }};

            const msg = "ctgrind frost harness message";

            const sig_share = try frost.round2Sign(
                std.heap.page_allocator, // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
                identifier,
                signing_share,
                group_public_key,
                nonces,
                msg,
                &commitment_list,
            );

            // Propagation witness.
            std.debug.print("sig_share={x}\n", .{sig_share.toBytes()});
        },
    }
}
