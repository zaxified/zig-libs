// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence this module's `SPEC.md`
//! "Const-time posture" paragraph (Phase 2d section) never had a measured
//! instrument behind it, and audit item A5 explicitly says so: "there is no
//! dudect-class harness in this toolchain" (`SPEC.md` line ~741, quoted in
//! full below). This file is that harness. Run it through
//! `../../../scripts/ctgrind.sh threshold_ecdsa` once the coordinator wires
//! the `TARGETS`/`MODES`/`PATTERN`/`LABEL` entries suggested at the bottom
//! of this comment — until then, drive it directly:
//!
//!     zig build ctgrind -Dctgrind-module=threshold_ecdsa -Dctgrind-valgrind=true
//!     valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!         zig-out/ctgrind/ctgrind-threshold_ecdsa <target> <taint>
//!
//! NOT wired into `zig build test-threshold_ecdsa` — memcheck's context
//! count is valgrind's own verdict, not something a Zig test can assert on.
//! `zig build check-ctgrind` compiles this (Debug, `-fvalgrind` forced on)
//! so it cannot rot into an unbuildable recipe; that compile is not a
//! measurement (see `scripts/ctgrind.sh`'s own header).
//!
//! ## Why `signWithShares`, not the private per-round helpers
//!
//! The two lines this harness exists to settle live in `signing.zig`'s
//! PRIVATE `provePoK`:
//!
//!   signing.zig:267  const r_full = Secp256k1.basePoint.mul(nonce.toBytes(.big), .big) catch continue;
//!   signing.zig:508  const big_gamma_pt = Secp256k1.basePoint.mul(gamma_i.toBytes(.big), .big) catch return error.IdentityPoint;
//!
//! (line 508 lives in `signWithShares` itself, not `provePoK` — both are
//! secret-scalar `basePoint.mul` call sites in this file.) `provePoK`,
//! `verifyPoK`, `commitGamma` and `pokChallenge` are all file-private
//! (`fn`, not `pub fn`); Zig's privacy model makes them invisible to any
//! file outside `signing.zig`, including this one, and this pass is not
//! permitted to edit `modules/threshold_ecdsa/src/*.zig` to export them.
//! So the only PUBLIC entry point that actually executes those two lines is
//! `signing.signWithShares` itself — the real, shipped, end-to-end GG20
//! online-signing driver, Paillier keygen and all. That is what both
//! targets below drive. This is heavier than the other modules' harnesses
//! (a real 2048-bit Paillier keypair + a 2048-bit ring-Pedersen aux tuple
//! per party, per run — the audit-F2 floor `AuxParams.validate`/
//! `paillierNMeetsFloor` enforces requires it; a smaller modulus makes the
//! checked-MtA path fail closed with `error.InvalidAuxParams` before either
//! disputed line is ever reached), but it is real code, not a stand-in.
//! `t = n = 2` (mirrors `signing.zig`'s own "gamma_i values that sum to
//! zero" test) keeps the pairwise MtA/MtAwc loop to its minimum: 2 ordered
//! pairs.
//!
//! ## What prompted this file: a disputed triage claim, now settled
//!
//! A prior triage pass claimed `signing.zig` "reintroduces a fixed
//! vulnerability class" by calling `std.crypto.ecc.Secp256k1.mul(...) catch
//! ...` directly on secret scalars instead of routing through the sibling
//! `k256` module. That claim does not survive reading `k256`'s own harness
//! doc comment: `k256`'s `Secp256k1.mul`/`combMulBase`
//! (`modules/k256/src/group.zig:277`/`:346`) end in `try
//! q.rejectIdentity()` too, and MEASURED (`k256`'s own table, 2026-08-13)
//! that this produces exactly the SAME shape of small, expected, non-zero
//! context count as std's. Confirmed directly for THIS module by reading
//! std's own source: `std.crypto.ecc.Secp256k1.mul`
//! (`lib/std/crypto/pcurves/secp256k1.zig:430`, the exact function
//! `signing.zig` calls at both disputed lines) bottoms out in `pcMul16`,
//! which ends at line 408 with the identical `try q.rejectIdentity()` — the
//! SAME one-bit "did the whole ladder land on the group identity"
//! validation `k256`'s own ladder performs, not a differently-shaped
//! branch. Routing through `k256` would not remove this branch; it would
//! just move which file's name shows up in the stack. The measurement
//! below is what actually settles whether it fires here, and where.
//!
//! ## The two targets
//!
//! * `share` — taints ONLY `secret_share` (`x_i`, "the signing share" —
//!   `KeyShare`'s own doc comment's term) on every `KeyShare` passed to
//!   `signWithShares`, keeping every draw from `random` itself real
//!   (untainted). This is the LONG-TERM secret: it flows into `w_i =
//!   λ_i·secret_share` (`Scalar.mul`, pure field arithmetic — no curve
//!   `mul`), into every `runCheckedMtAwc`'s Paillier-encrypted witness, and
//!   into the final `s_i = m·k_i + r·σ_i` accumulation. It never itself
//!   becomes the argument of a `basePoint.mul` call in this file.
//! * `nonce` — taints exactly the first `3*t` 48-byte draws from `random`,
//!   in call order: `k_i`,`γ_i` for each party (Phase 1, 2 draws/party)
//!   then `provePoK`'s own internal Schnorr nonce for each party (Phase 2,
//!   1 draw/party, assuming its `IdentityElement` retry never fires — it is
//!   a q⁻¹-probability event and does not fire with the seed used here).
//!   Every OTHER `random` draw in the run — `mta.zig`'s own `randomScalar`
//!   (Bob's `beta_prime`, drawn TWICE per ordered pair via the SAME 48-byte
//!   idiom: `mta.zig:181`/`:359`) and every Paillier/range-proof mask —
//!   stays real. `TaintFirstN` below counts 48-byte draws in ARRIVAL order
//!   and stops tainting once the budget is spent, rather than assuming a
//!   fixed total call count, so `beta_prime`'s later 48-byte draws are
//!   deliberately excluded, not accidentally missed. This is what actually
//!   exercises signing.zig:267 (the PoK nonce) and signing.zig:508 (`γ_i`
//!   itself) with tainted input; `secret_share` stays real in this target.
//!
//! Both targets run the REAL `keygenTrustedDealer` first (Phase 2a — a
//! genuine Shamir+Feldman split and two genuine 2048-bit Paillier
//! keypairs), so nothing about the secret material's shape is synthetic:
//! only which bytes are marked undefined, and when, differs from an
//! ordinary call.
//!
//! ## The result is only meaningful next to two controls
//!
//! Per (target, mode): the CLAIM row (`taint=yes`, built `-fvalgrind`), an
//! UNTAINTED negative control (`taint=no`, same build), and a
//! no-`-fvalgrind` TRAP (`taint=yes`, built without the switch — see
//! `scripts/ctgrind.sh`'s header for why: `std.valgrind.doClientRequest`
//! silently no-ops without it). A zero in the claim row means nothing
//! unless the control is also zero (rules out "the pattern matches
//! everything") and the trap is also zero with a non-zero total elsewhere
//! (rules out "the switch was never on").
//!
//! `std.debug.print`ing `sig.r`/`sig.s` (or the abort error) after the call
//! is the propagation witness, same convention as every other harness here:
//! it is NOT constant-time, so a tainted byte reaching it produces contexts
//! of its own, and seeing those is what makes an in-file zero mean "no
//! branch found" rather than "the taint never arrived". Downstream of a
//! REAL `basePoint.mul`, memcheck's V-bits propagate through the rest of
//! the arithmetic (`r`, `s_i`, `s`) even though every one of those is a
//! value the protocol legitimately reveals — so `sig.verify`'s OWN
//! canonicality checks (std's `ecdsa.zig`/`pcurves/common.zig`) are
//! expected to show up too, on public output the scheme is SUPPOSED to
//! disclose. That is exactly the discriminator this file's report applies
//! per context: "branches on a secret byte" vs. "branches on a value the
//! output discloses anyway" (see `slhdsa`'s harness for the canonical case
//! of the second kind reporting non-zero for no reason that matters).
//!
//! ## What SPEC.md already claims, quoted exactly (not paraphrased)
//!
//! `SPEC.md`'s Phase 2d "Const-time posture" paragraph: "`k_i`/`γ_i`/`w_i`/
//! `s_i` and every MtA/MtAwc intermediate are SECRET and flow entirely
//! through already-constant-time primitives this module established in
//! Phase 2b/2c (`Scalar.add`/`.mul`/`.invert`, `paillier`'s constant-time
//! `pow`/homomorphic ops, `ff`'s constant-time `powWithEncodedExponent`) —
//! `signing.zig` introduces no new secret-touching arithmetic beyond
//! composing those calls and the Schnorr NIZK's own nonce/response (`k +
//! e·γ`, plain `Scalar` ops)." That paragraph does not mention
//! `basePoint.mul`/`rejectIdentity` at all — it is silent on the exact
//! question this harness measures, not wrong about it. Separately, audit
//! item A5 in the "Auditor brief" section states plainly: "there is no
//! dudect-class harness in this toolchain" — true until this file, about a
//! DIFFERENT question (`paillier.decrypt`'s `L`-function division), not
//! this one; it is quoted here only because it is the one sentence in this
//! module's docs that names the general absence this harness closes.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const paillier = @import("paillier");

const Scalar = root.Scalar;
const KeyShare = root.KeyShare;
const signing = root.signing;

// ── fixture construction (REAL Phase 2a keygen; no reimplemented crypto —
// same idiom `signing.zig`'s own end-to-end tests use, rebuilt here from
// PUBLIC root.zig/paillier APIs only, since the test file's private
// `testAuxParams`/`sampleFeBelow` helpers are not visible from this file
// either) ────────────────────────────────────────────────────────────────

/// Draws a uniform `AuxFe` below `m`'s modulus — `root.zig`'s own private
/// `sampleFeBelow`, reproduced here because it is not `pub`. Not itself
/// secret-touching in a way this harness measures (the ring-Pedersen tuple
/// `(Ñ,h1,h2)` this builds is broadcast PUBLIC material, never tainted).
fn sampleFeBelow(m: root.AuxModulus, random: std.Random) root.AuxFe {
    const n_bits = m.bits();
    const n_len = (n_bits + 7) / 8;
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const r = root.AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (!r.isZero()) return r;
    }
}

/// Fast (non-safe-prime) ring-Pedersen aux tuple — `signing.zig`'s own
/// private `testAuxParams`, reproduced for the same reason as above. `h2 =
/// h1^2` for a known lambda=2: fine for driving the checked-MtA
/// ARITHMETIC (which is what this harness measures), not a claim about
/// `generateAuxParams`'s real safe-prime search.
fn fixtureAuxParams(random: std.Random) !root.AuxParams {
    const nt_kp = try paillier.generate(random, 2048);
    var nt_buf: [paillier.modulus_bytes]u8 = undefined;
    const nt_len = nt_kp.public.nByteLen();
    try nt_kp.public.nToBytes(nt_buf[0..nt_len]);
    var strip: usize = 0;
    while (strip < nt_len and nt_buf[strip] == 0) : (strip += 1) {}
    const n_tilde = try root.AuxModulus.fromBytes(nt_buf[strip..nt_len], .big);
    const x = sampleFeBelow(n_tilde, random);
    const h1 = n_tilde.sq(x);
    const h2 = n_tilde.sq(h1);
    return .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 };
}

const Fixture = struct {
    key_shares: []root.KeyShare,

    fn deinit(self: Fixture, allocator: std.mem.Allocator) void {
        allocator.free(self.key_shares[0].public_keys.entries);
        allocator.free(self.key_shares);
    }
};

/// `t = n = 2` trusted-dealer keygen, real 2048-bit Paillier keys (the
/// audit-F2 floor requires `N > q⁷`; a smaller modulus makes the checked
/// path fail closed before either disputed line runs). `setup_random` is
/// deliberately a SEPARATE, always-real random source from whatever
/// `random` the caller later hands to `signWithShares` — Phase 2a keygen
/// is not what either target measures, so nothing here is ever tainted.
fn buildFixture(allocator: std.mem.Allocator, setup_random: std.Random) !Fixture {
    const n: u32 = 2;
    const t: u32 = 2;
    var paillier_keys: [2]paillier.KeyPair = undefined;
    var aux_params: [2]root.AuxParams = undefined;
    for (0..n) |i| {
        paillier_keys[i] = try paillier.generate(setup_random, 2048);
        aux_params[i] = try fixtureAuxParams(setup_random);
    }

    const secret = randomScalar(setup_random);
    var coefficients: [1]Scalar = undefined;
    coefficients[0] = randomScalar(setup_random);

    const key_shares = try root.keygenTrustedDealer(allocator, t, n, secret, &coefficients, &paillier_keys, &aux_params);
    return .{ .key_shares = key_shares };
}

/// Same 48-byte wide-reduction idiom `signing.zig`'s own private
/// `randomScalar` uses (and `mta.zig`'s, and `zkproofs.zig`'s) — used here
/// only to build the fixture's dealer secret/coefficients, which are never
/// tainted in either target.
fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

// ── target "nonce": taint the first 3*t 48-byte draws from `random` ───────

/// Wraps a real PRNG. Every `.bytes()` call is served with GENUINE random
/// bytes from `inner` (never fabricated), then — for exactly the first
/// `taint_budget` calls whose length is 48 (this module's fixed width for
/// every `Zq` scalar draw: `signing.zig`/`mta.zig`/`zkproofs.zig`'s shared
/// `randomScalar` idiom) — marked undefined via
/// `std.valgrind.memcheck.makeMemUndefined` before the caller ever reads
/// them. The mark happens INSIDE this callback, before any consumer sees
/// the bytes, so there is no window for a from-before-tainting defined copy
/// to survive (the concern `ct25519`'s/`k256`'s `reloadVolatile` defends
/// against) — the memory is never observably defined outside this
/// function. Draws of any OTHER length (Paillier/range-proof randomness,
/// hundreds of bytes wide) are never counted against the budget and never
/// tainted, so `mta.zig`'s own 48-byte `beta_prime` draws (Phase 3, AFTER
/// the budget is spent for realistic `t`) are excluded by construction,
/// not by luck.
const TaintFirstN = struct {
    inner: std.Random,
    taint_budget: usize,
    taint_calls_48: usize = 0,
    total_calls_48: usize = 0,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *TaintFirstN = @ptrCast(@alignCast(ptr));
        self.inner.bytes(buf);
        if (buf.len == 48) {
            self.total_calls_48 += 1;
            if (self.taint_calls_48 < self.taint_budget) {
                std.valgrind.memcheck.makeMemUndefined(buf);
                self.taint_calls_48 += 1;
            }
        }
    }

    fn random(self: *TaintFirstN) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

// ── the harness proper ────────────────────────────────────────────────────

const Target = enum { share, nonce };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "share")) return .share;
    if (std.mem.eql(u8, s, "nonce")) return .nonce;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn printOutcome(result: signing.SignError!signing.Signature) void {
    if (result) |sig| {
        std.debug.print("r={x} s={x}\n", .{ sig.r, sig.s });
    } else |err| {
        // Formatted regardless of taint state: still the propagation
        // witness (the error NAME is fixed at comptime, but reaching this
        // branch at all after a tainted run is itself informative, and
        // `{t}` still touches std's error-name formatter).
        std.debug.print("aborted: {t}\n", .{err});
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const allocator = da.allocator();

    // Fixture setup randomness is ALWAYS real — Phase 2a keygen is not
    // measured here (see buildFixture's doc comment).
    var setup_prng = std.Random.DefaultPrng.init(0x746872_65735f65); // "thres_e"
    const setup_random = setup_prng.random();

    const fixture = try buildFixture(allocator, setup_random);
    defer fixture.deinit(allocator);

    const message = "ctgrind harness message — threshold_ecdsa Phase 2d";

    switch (target) {
        .share => {
            // "The signing share": KeyShare.secret_share (x_i), tainted
            // directly on each party's struct field. Every draw from
            // `sign_random` below stays real — this target isolates the
            // LONG-TERM secret, not the per-signature ephemeral one.
            if (tainted) {
                for (fixture.key_shares) |*ks| {
                    std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&ks.secret_share));
                }
            }
            var sign_prng = std.Random.DefaultPrng.init(0x7368617265); // "share"
            const sign_random = sign_prng.random();

            const result = signing.signWithShares(allocator, fixture.key_shares, message, sign_random);
            printOutcome(result);
        },
        .nonce => {
            // "The per-signature nonce": the first 3*t = 6 draws from
            // `random` — k_i, gamma_i (Phase 1) then provePoK's own
            // ephemeral Schnorr nonce (Phase 2), for each of the t=2
            // parties, in that order. secret_share stays real.
            var inner_prng = std.Random.DefaultPrng.init(0x6e6f6e6365); // "nonce"
            var wrapper: TaintFirstN = .{
                .inner = inner_prng.random(),
                .taint_budget = if (tainted) 3 * fixture.key_shares.len else 0,
            };
            const sign_random = wrapper.random();

            const result = signing.signWithShares(allocator, fixture.key_shares, message, sign_random);
            printOutcome(result);

            // Self-check on the assumption the doc comment above states:
            // exactly 3*t 48-byte draws should have occurred before this
            // point plus however many Phase-3 `beta_prime` draws followed.
            // Printed unconditionally (not gated on `tainted`) so a
            // `taint=no` run reports the same total_calls_48 as a sanity
            // cross-check between the two builds.
            std.debug.print("draws_48b_total={d} draws_48b_tainted={d}\n", .{
                wrapper.total_calls_48,
                wrapper.taint_calls_48,
            });
        },
    }
}

// ── suggested scripts/ctgrind.sh config (for the coordinator to paste in;
// this file does not and must not edit that script itself) ───────────────
//
// declare -A TARGETS=(
//     [threshold_ecdsa]="share nonce"
// )
// declare -A MODES=(
//     [threshold_ecdsa]="ReleaseFast"
// )
// declare -A PATTERN=(
//     # VERIFIED against real `valgrind --tool=memcheck` logs for both
//     # targets (2026-09-09): every context in both claim rows classifies
//     # into in-file or WITNESS with this pattern — zero `unattr` — so this
//     # is not a guess. It is wide because this module's own dependency
//     # surface is wide: this module's own 4 files, PLUS every file the
//     # REAL end-to-end run actually passes tainted-derived data through —
//     # `paillier`'s homomorphic ops and its `root.zig` (SAME basename as
//     # this module's own `root.zig`; deliberately not disambiguated, same
//     # as `chachapoly/aead` naming std's files — see this harness's own
//     # doc comment), `montint`/`std.crypto.ff`'s modexp (ring-Pedersen /
//     # range-proof commitments), std's secp256k1 ladder (both disputed
//     # `basePoint.mul` lines) AND `common.zig`/`ecdsa.zig` (the final
//     # signature's own std-ECDSA self-verify, Phase 2d step 6), plus the
//     # big-int/mem plumbing (`mem.zig`/`int.zig`/`math.zig`/`memcpy.zig`/
//     # `memmove.zig`/`compiler_rt.zig`) every one of those calls through.
//     # Identical for both targets: the SAME dependency files show up
//     # regardless of which secret is tainted, because both `share` and
//     # `nonce` eventually flow into the same final `sig.verify()`.
//     [threshold_ecdsa/share]='signing[.]zig|root[.]zig|mta[.]zig|zkproofs[.]zig|montint[.]zig|asm_core[.]zig|limbs[.]zig|ff[.]zig|secp256k1[.]zig|secp256k1_64[.]zig|secp256k1_scalar_64[.]zig|common[.]zig|ecdsa[.]zig|scalar[.]zig|mem[.]zig|int[.]zig|math[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
//     [threshold_ecdsa/nonce]='signing[.]zig|root[.]zig|mta[.]zig|zkproofs[.]zig|montint[.]zig|asm_core[.]zig|limbs[.]zig|ff[.]zig|secp256k1[.]zig|secp256k1_64[.]zig|secp256k1_scalar_64[.]zig|common[.]zig|ecdsa[.]zig|scalar[.]zig|mem[.]zig|int[.]zig|math[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
// )
// declare -A LABEL=(
//     [threshold_ecdsa/share]='threshold_ecdsa signing share (x_i)+paillier+std ecdsa'
//     [threshold_ecdsa/nonce]='threshold_ecdsa per-sig nonce (k_i/gamma_i/PoK)+paillier+std ecdsa'
// )
//
// Measured (ReleaseFast, `t=n=2`, this pass, 2026-09-09):
//   share: total=129 in=127 witness=2 unattr=0 (control=0, trap=0)
//   nonce: total=404 in=400 witness=4 unattr=0 (control=0, trap=0)
// Full per-context breakdown, class judgement (branches-on-a-secret-byte vs.
// branches-on-a-value-the-output-discloses-anyway) and the rejectIdentity
// tally are in this pass's harness report, not repeated here — a source
// comment is the wrong place for a table that will be stale the moment the
// code changes; `ctgrind-expected.tsv`'s pinned digest is what should catch
// that, once the coordinator wires this in.
