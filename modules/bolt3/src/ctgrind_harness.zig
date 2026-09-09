// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Threat model
//! sentence: "No secret-dependent branching beyond `std.crypto.ecc`'s
//! constant-time scalar ladder." Until this file existed that sentence had
//! nothing behind it but the ladder's own reputation. Run it through
//! `zig build ctgrind -Dctgrind-module=bolt3 -Dctgrind-valgrind=true
//! -Doptimize=ReleaseFast` (and `-Dctgrind-valgrind=false` for the trap row);
//! `bolt3` has no entry in `scripts/ctgrind.sh` yet, so it cannot be driven by
//! name until the coordinator adds one. Not wired into `zig build
//! test-bolt3`: memcheck's context count is valgrind's own verdict, not
//! something a Zig test can assert on.
//!
//! Usage: ctgrind-bolt3 <target> <yes|no>
//!   targets: derive | revocation | shachain | shachain_index
//!
//! ## What each target drives, through the module's real public API
//!
//! * `derive` — `derivePrivateKey(basepoint_secret, per_commitment_secret)`,
//!   BOTH 32-byte arguments tainted. This is not one scalar op: the function
//!   runs `Scalar.fromBytes` on `basepoint_secret` directly AND calls
//!   `pointOf` (`k256`'s `combMulBase`) on EACH of the two secrets to build
//!   the public points the hash is taken over, before the final
//!   `b.add(t)`. So a single call exercises k256's comb ladder twice on two
//!   independent secret scalars plus one scalar add — the whole "scalar
//!   arithmetic directly on two independent secret scalars" surface the
//!   audit brief named.
//! * `revocation` — `deriveRevocationPrivateKey(revocation_basepoint_secret,
//!   per_commitment_secret)`, both tainted. Same shape: two `pointOf` calls
//!   (one per secret) plus `rbs.mul(h1).add(pcs.mul(h2))` — two scalar muls
//!   by PUBLIC hash-derived scalars and a scalar add, both operands secret.
//! * `shachain` — `perCommitmentSecret(seed, index)` with `seed` tainted and
//!   `index` held PUBLIC at `bolt3.max_index` (all 48 bits set — the deepest
//!   loop, matching the Appendix D "final node" vector). This is the row that
//!   answers the disputed triage claim below.
//! * `shachain_index` — the same function with `seed` left UNTAINTED and
//!   `index`'s bytes tainted instead. Not a claim about a real threat (see
//!   the verdict below) — it is the positive control that proves the harness
//!   CAN see the index-driven branch at all, so `shachain`'s zero (if it is
//!   zero) means "no branch on the secret", not "this harness cannot detect
//!   branches in this function".
//!
//! ## The disputed triage claim: is `index` secret?
//!
//! A prior triage pass flagged `perCommitmentSecret` as "branching on
//! `index`" and a rebuttal argued the index is public commitment-number
//! metadata. Reading the code and the wider protocol rather than taking
//! either on faith:
//!
//! `perCommitmentSecret`'s loop body is exactly `if ((index >> b) & 1 == 1)
//! { flip bit b of p; p = SHA256(p); }` (`root.zig:150`) — the loop TRIP
//! COUNT is fixed at 48 regardless of `index` (no early exit), but which
//! iterations run the hash body is a direct, unmasked branch on `index`
//! bits. If `index` carried confidentiality requirements this would be a
//! real leak, full stop — there is no ambiguity about what the code does.
//!
//! The ambiguity is entirely about the THREAT MODEL, and BOLT#3 answers it:
//! the per-commitment index is the channel's commitment-number counter, a
//! monotonic value both channel peers already track as ordinary protocol
//! state (it is what `revoke_and_ack` is revealing the secret FOR — a peer
//! asking "give me the secret for commitment N" already knows N). It is
//! deliberately NOT given confidentiality treatment anywhere else in BOLT#3
//! either: the commitment transaction's obscured number
//! (`obscured_commitment_transaction_number`, BOLT#3 "Commitment
//! Transaction") only XOR-masks it against blockchain observers who are not
//! a channel party, using a value derived from the two funding pubkeys — a
//! completely different mechanism from side-channel confidentiality, and one
//! that does not exist to hide the index from the counterparty or from the
//! local process computing this function. `SPEC.md`'s own threat model
//! ("inputs are keys/secrets a channel peer already holds") backs the same
//! reading: the peer calling `perCommitmentSecret` locally, or receiving its
//! output, already knows which index it asked for.
//!
//! **Verdict: `index` is public within this function's threat model, and the
//! branch on it is not a finding.** The `seed` — and every byte of the
//! returned per-commitment secret chain — is the thing that must not leak,
//! and the `shachain` target below taints exactly that and nothing else.
//! `shachain_index` exists only so that verdict is measured, not asserted:
//! if `shachain` reads a small in-file count and `shachain_index` reads a
//! LARGER one on the same code, that difference is the demonstration that
//! the zero (or near-zero) on `seed` alone is not an artifact of the harness
//! being blind to this function.
//!
//! ## Why the pattern should name k256's files too
//!
//! `derive` and `revocation` DELEGATE their scalar multiplication to k256's
//! `combMulBase` (via `pointOf`) and their scalar add/mul to k256's
//! re-exported std `Scalar`. That delegation's constant-time property is
//! this module's property for every byte that flows through it — the same
//! reasoning `bolt8`'s pattern already states for the same dependency.
//! Expect (not a finding, precedent from `k256/comb`'s own harness):
//! * `group.zig`'s `try acc.rejectIdentity()` after each `combMulBase` call —
//!   the "did this scalar multiply land on the neutral element" one-bit
//!   check, ~2^-256 by construction, present per `pointOf` call (two per
//!   `derive`/`revocation` invocation).
//! * `common.zig`'s `rejectNonCanonical` (`crypto.timing_safe.compare(...) !=
//!   .lt`) inside `Scalar.fromBytes`, reached once per raw secret this module
//!   feeds directly into `Scalar.fromBytes` (`basepoint_secret` in `derive`;
//!   `revocation_basepoint_secret` AND `per_commitment_secret` in
//!   `revocation`, both hit through `Scalar.fromBytes` at the top of
//!   `deriveRevocationPrivateKey`) — the scalar-canonicality validation every
//!   module built on this std scalar type carries, tracked in this campaign
//!   as an accepted class, not a defect.
//!
//! `shachain`/`shachain_index` touch neither k256 nor std's scalar type at
//! all (pure `root.zig` bit-twiddling + `std.crypto.hash.sha2.Sha256`), so
//! their pattern should be `root[.]zig` alone; a nonzero SHA-256 context
//! would be new information, not a known class.
//!
//! ## Suggested `scripts/ctgrind.sh` config (coordinator wires these)
//!
//!     TARGETS: [bolt3]="derive revocation shachain shachain_index"
//!     MODES:   [bolt3]="ReleaseFast"
//!     PATTERN: [bolt3/derive]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
//!              [bolt3/revocation]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
//!              [bolt3/shachain]='root[.]zig'
//!              [bolt3/shachain_index]='root[.]zig'
//!     LABEL:   [bolt3/derive]='bolt3 derivePrivateKey (bs+pcs)+k256'
//!              [bolt3/revocation]='bolt3 deriveRevocationPrivateKey (rbs+pcs)+k256'
//!              [bolt3/shachain]='bolt3 perCommitmentSecret (seed only, index public)'
//!              [bolt3/shachain_index]='bolt3 perCommitmentSecret (index tainted, sanity control)'
//!
//! ## The two traps every harness in this repo has to defend against
//!
//! 1. `std.valgrind.doClientRequest` opens with `if (!builtin.valgrind_support)
//!    return default;`, off by default outside Debug. Built WITHOUT
//!    `-fvalgrind`, `makeMemUndefined` is a no-op and every row silently reads
//!    zero regardless of what the code does. Measure both ways; the
//!    no-`-fvalgrind` row is the trap check, not a control.
//! 2. Debug/ReleaseSafe turn k256's field/scalar limb arithmetic's checked
//!    operators into overflow branches on secret-derived values (the exact
//!    reason `k256`'s own harness states ReleaseFast only), so this harness
//!    states the same restriction and is not meant to be run any other way.
//! 3. `reloadVolatile` forces one real load from freshly-tainted memory
//!    immediately before the call under test, so the optimizer cannot feed
//!    the ladder a defined copy left over from before `makeMemUndefined`
//!    ran. Defensive, not demonstrated to be necessary on this compiler —
//!    same status `ct25519`'s harness documents for its own copy of this
//!    guard.
//!
//! ## The propagation proof
//!
//! Every target formats its result through `std.debug.print`, which is not
//! constant-time by design (digit/hex formatting branches on the value being
//! printed). Seeing THAT print's contexts nonzero is what proves the taint
//! travelled secret -> output -> stdout, so an in-file zero means "no branch
//! found", not "the taint never arrived" — see `scripts/ctgrind.sh`'s WITNESS
//! bucket.

const std = @import("std");
const builtin = @import("builtin");
const bolt3 = @import("root.zig");

const Target = enum { derive, revocation, shachain, shachain_index };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "derive")) return .derive;
    if (std.mem.eql(u8, s, "revocation")) return .revocation;
    if (std.mem.eql(u8, s, "shachain")) return .shachain;
    if (std.mem.eql(u8, s, "shachain_index")) return .shachain_index;
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

/// Force a volatile reload so the optimizer cannot feed the code under test a
/// defined register/spill copy of memory we just marked undefined — the same
/// guard every other harness in this repository carries.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// Deterministic secret material, computed at runtime (not folded at
/// comptime) so tainting it marks memory the code under test actually reads.
/// Domain-separated per role so `derive`/`revocation`'s two independent
/// secrets are never accidentally the same bytes.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// A 32-byte BIG-ENDIAN scalar comfortably inside `[1, n)`: clearing the
/// top (most-significant, i.e. index-0) byte keeps the value below the
/// secp256k1 group order without inspecting it, mirroring `k256`'s own
/// harness (`secretScalar`), which masks the same position for the same
/// `.big`-endian convention this module uses throughout.
fn secretScalar(comptime domain: []const u8) [32]u8 {
    var s = secretBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .derive => {
            var bs = secretScalar("ctgrind-bolt3-harness-basepoint-secret-v1");
            var pcs = secretScalar("ctgrind-bolt3-harness-per-commitment-secret-v1");
            taintIf(tainted, &bs);
            taintIf(tainted, &pcs);
            const basepoint_secret = reloadVolatile(32, &bs);
            const per_commitment_secret = reloadVolatile(32, &pcs);

            const out = try bolt3.derivePrivateKey(basepoint_secret, per_commitment_secret);
            std.debug.print("privkey={x}\n", .{out});
        },
        .revocation => {
            var rbs = secretScalar("ctgrind-bolt3-harness-revocation-basepoint-secret-v1");
            var pcs = secretScalar("ctgrind-bolt3-harness-revocation-per-commitment-secret-v1");
            taintIf(tainted, &rbs);
            taintIf(tainted, &pcs);
            const revocation_basepoint_secret = reloadVolatile(32, &rbs);
            const per_commitment_secret = reloadVolatile(32, &pcs);

            const out = try bolt3.deriveRevocationPrivateKey(revocation_basepoint_secret, per_commitment_secret);
            std.debug.print("revprivkey={x}\n", .{out});
        },
        .shachain => {
            // `seed` is the secret under test; `index` is held PUBLIC (see the
            // verdict above) at `max_index` so the loop runs its deepest path
            // (all 48 bits set, the Appendix D "final node" case) — the
            // largest surface this function's own code offers.
            var sd = secretBytes(32, "ctgrind-bolt3-harness-shachain-seed-v1");
            taintIf(tainted, &sd);
            const seed = reloadVolatile(32, &sd);

            const out = bolt3.perCommitmentSecret(seed, bolt3.max_index);
            std.debug.print("secret={x}\n", .{out});
        },
        .shachain_index => {
            // Mirror image of `shachain`: `seed` stays untainted throughout,
            // and `index`'s encoding is what gets marked undefined instead.
            // This is the positive control for the verdict above, not a
            // claim about a real secret — see the module doc comment.
            const seed = secretBytes(32, "ctgrind-bolt3-harness-shachain-index-control-seed-v1");

            var idx_bytes: [6]u8 = undefined;
            std.mem.writeInt(u48, &idx_bytes, bolt3.max_index, .big);
            taintIf(tainted, &idx_bytes);
            const idxr = reloadVolatile(6, &idx_bytes);
            const index = std.mem.readInt(u48, &idxr, .big);

            const out = bolt3.perCommitmentSecret(seed, index);
            std.debug.print("secret={x}\n", .{out});
        },
    }
}
