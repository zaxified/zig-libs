// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence this module's `SPEC.md`
//! "Const-time posture" paragraph (Phase 2d section) never had a measured
//! instrument behind it, and audit item A5 explicitly says so: "there is no
//! dudect-class harness in this toolchain" (`SPEC.md` line ~741, quoted in
//! full below). This file is that harness. Run it through
//! `../../../scripts/checks/ctgrind.sh threshold_ecdsa` once the coordinator wires
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
//! measurement (see `scripts/checks/ctgrind.sh`'s own header).
//!
//! ## What it drives (rewritten 2026-10-02)
//!
//! Until 2026-10-02 the targets drove `signing.signWithShares`, then a single
//! function computing every party's values, and tainted draws from the one
//! `random` it took. `signWithShares` is now a loop over `presign.Party`
//! state machines, each drawing from its own CSPRNG seeded up front — a
//! wrapper around the caller's `random` would see only the seeds. So the
//! harness runs the parties itself (`runProtocol`, the same routing
//! `signWithShares` does), handing each party its own wrapped PRNG, and
//! taints at the source of every secret draw. `t = n = 2`: 2 parties,
//! 2 ordered pairs.
//!
//! The secret-scalar `mul` sites this reaches are all in `presign.zig`,
//! `ecproofs.zig` and `zkproofs.zig` (`γ_i·G`, `k_i·R`, `σ_i·R`, the
//! Pedersen/ST/Schnorr nonces, `alpha·R` in the PDL proof), each through
//! std's `Secp256k1.mul`, which ends in the one-bit `rejectIdentity` check
//! the comment below discusses.
//!
//! ## Why std's `Secp256k1.mul` is the right ladder here
//!
//! A prior triage pass claimed this module "reintroduces a fixed
//! vulnerability class" by calling `std.crypto.ecc.Secp256k1.mul(...) catch
//! ...` directly on secret scalars instead of routing through the sibling
//! `k256` module. That claim does not survive reading `k256`'s own harness
//! doc comment: `k256`'s `Secp256k1.mul`/`combMulBase`
//! (`modules/k256/src/group.zig:277`/`:346`) end in `try
//! q.rejectIdentity()` too, and MEASURED (`k256`'s own table, 2026-08-13)
//! that this produces exactly the SAME shape of small, expected, non-zero
//! context count as std's. Confirmed directly for THIS module by reading
//! std's own source: `std.crypto.ecc.Secp256k1.mul`
//! (`lib/std/crypto/pcurves/secp256k1.zig:430`) bottoms out in `pcMul16`,
//! which ends at line 408 with the identical `try q.rejectIdentity()` — the
//! SAME one-bit "did the whole ladder land on the group identity"
//! validation `k256`'s own ladder performs, not a differently-shaped
//! branch. Routing through `k256` would not remove this branch; it would
//! just move which file's name shows up in the stack.
//!
//! ## The three targets
//!
//! * `share` — taints ONLY `secret_share` (`x_i`) on every `KeyShare`,
//!   before the parties are built; every random draw stays real. The
//!   LONG-TERM secret: it flows into `w_i = λ_i·x_i`, into the MtAwc
//!   witness and `W_i` consistency, and into `σ_i`.
//! * `nonce` — taints EVERY 48-byte draw of every party: this module's width
//!   for a `Zq` secret scalar — `k_i`, `γ_i`, `ℓ_i`, and the nonces of the
//!   Pedersen, Schnorr and ST proofs. `x_i` stays real. The draw count is
//!   printed (`draws_48b_*`).
//! * `betaprime` — taints every 160-byte draw: Bob's MtA blind
//!   `β' ∈ [0, q⁵)` (audit F5), `2·t(t−1)` = 4 at `t = 2` — one MtA and one
//!   MtAwc per ordered pair. The count is checked before the result is
//!   printed (`TaintBetaPrime`). Positive control, measured on the old
//!   driver (2026-09-15): a `testb`/`je` on `β'[100]` inserted after the draw
//!   added exactly 2 contexts, both on the inserted line, one per caller.
//!
//! Every target runs the REAL `keygenTrustedDealer` first (a genuine
//! Shamir+Feldman split and two genuine 2048-bit Paillier keypairs), so
//! nothing about the secret material's shape is synthetic: only which bytes
//! are marked undefined, and when, differs from an ordinary run.
//!
//! ## The result is only meaningful next to two controls
//!
//! Per (target, mode): the CLAIM row (`taint=yes`, built `-fvalgrind`), an
//! UNTAINTED negative control (`taint=no`, same build), and a
//! no-`-fvalgrind` TRAP (`taint=yes`, built without the switch — see
//! `scripts/checks/ctgrind.sh`'s header for why: `std.valgrind.doClientRequest`
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
    const h2 = n_tilde.sq(x);
    const h1 = n_tilde.sq(h2); // h1 ∈ ⟨h2⟩, as generateAuxParams
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

// ── target "nonce": taint every 48-byte draw ─────────────────────────────

/// Wraps a real PRNG. Every `.bytes()` call is served with GENUINE random
/// bytes from `inner` (never fabricated); a 48-byte call — this module's
/// fixed width for a `Zq` secret scalar (`presign.zig`, `ecproofs.zig`,
/// `mta.zig`, `zkproofs.zig` all use the same `randomScalar` idiom) — is then
/// marked undefined via `std.valgrind.memcheck.makeMemUndefined` before the
/// caller reads it. The mark happens INSIDE this callback, so no defined copy
/// survives (the concern `ct25519`'s/`k256`'s `reloadVolatile` defends
/// against). Wider draws (Paillier/range-proof randomness, `β'`) are left
/// alone.
const TaintScalars = struct {
    inner: std.Random,
    taint: bool,
    draws: usize = 0,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *TaintScalars = @ptrCast(@alignCast(ptr));
        self.inner.bytes(buf);
        if (buf.len == 48) {
            self.draws += 1;
            if (self.taint) std.valgrind.memcheck.makeMemUndefined(buf);
        }
    }

    fn random(self: *TaintScalars) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

// ── target "betaprime": taint every draw of Bob's MtA blind β' ────────────

/// Since audit F5 (2026-09-16), Bob's blind `β'` is a uniform `[0, q⁵)` draw
/// of `zkproofs.beta_prime_bytes` = 160 bytes (`mta.sampleBetaPrime`). This
/// wrapper taints EVERY draw of exactly that width, and nothing else: scalars
/// are 48 bytes, the proof masks are `q³` (96), `q⁷` (224) or `q·Ñ`-wide,
/// and Paillier randomness is `|N|`. The total over all parties is checked
/// against `2·t(t−1)` in `main`, so a stale width assumption fails the row
/// instead of silently tainting nothing.
const TaintBetaPrime = struct {
    inner: std.Random,
    taint: bool,
    draws: usize = 0,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *TaintBetaPrime = @ptrCast(@alignCast(ptr));
        self.inner.bytes(buf);
        if (buf.len == root.zkproofs.beta_prime_bytes) {
            self.draws += 1;
            if (self.taint) std.valgrind.memcheck.makeMemUndefined(buf);
        }
    }

    fn random(self: *TaintBetaPrime) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

// ── the protocol, one party per share (what `signWithShares` does) ───────

const presign = root.presign;

fn runProtocol(allocator: std.mem.Allocator, shares: []const KeyShare, randoms: []const std.Random, message: []const u8) !signing.Signature {
    const t = shares.len;
    var indices: [2]u32 = undefined;
    for (shares, 0..) |s, i| indices[i] = s.index;
    const sid = [_]u8{0x5a} ** 32;

    var parties: [2]presign.Party = undefined;
    for (0..t) |i| parties[i] = try presign.Party.init(allocator, shares[i], indices[0..t], sid);
    defer for (parties[0..t]) |*p| p.deinit();

    var inboxes: [2]std.ArrayList([]const u8) = @splat(.empty);
    defer for (&inboxes) |*b| b.deinit(allocator);
    var boxes: [2]?presign.Outbox = @splat(null);
    defer for (boxes) |b| if (b) |o| o.deinit(allocator);

    for (0..6) |_| {
        var next: [2]?presign.Outbox = @splat(null);
        errdefer for (next) |b| if (b) |o| o.deinit(allocator);
        for (0..t) |i| next[i] = try parties[i].advance(inboxes[i].items, randoms[i]);
        for (boxes) |b| if (b) |o| o.deinit(allocator);
        boxes = next;
        for (&inboxes) |*b| b.clearRetainingCapacity();
        for (0..t) |from| {
            for (boxes[from].?.messages) |m| {
                for (0..t) |to| {
                    if (to == from) continue;
                    if (m.to) |dst| if (dst != indices[to]) continue;
                    try inboxes[to].append(allocator, m.bytes);
                }
            }
        }
    }
    var presigs: [2]presign.Presignature = undefined;
    var made: usize = 0;
    defer for (presigs[0..made]) |*p| p.deinit();
    for (0..t) |i| {
        presigs[i] = try parties[i].finish(inboxes[i].items);
        made += 1;
    }
    var sig_shares: [2][]u8 = undefined;
    var signed: usize = 0;
    defer for (sig_shares[0..signed]) |b| allocator.free(b);
    for (0..t) |i| {
        sig_shares[i] = try presigs[i].signShare(.{ .bytes = message });
        signed += 1;
    }
    var abort: ?presign.Abort = null;
    return presigs[0].public.combine(.{ .bytes = message }, sig_shares[0..t], &abort);
}

// ── target "fac": taint the Paillier factors through Πfac's prover ───────
//
// Dealer-free keygen (2026-10-02): every party proves its Paillier `N` has
// no small factor (`fac_proof.prove`), the one place outside `paillier`
// where the factors `p`, `q` are arithmetic inputs. Real 2048-bit material:
// tss-lib party 1's safe primes, party 2's ring-Pedersen tuple. Only `p`,
// `q` are tainted (the masks stay real); `N` is computed before the taint,
// as it is public. The printed `z1`/`z2`/`v` are the witness — public
// responses into which `p`/`q` flow.

fn unhexInto(buf: []u8, hex: []const u8) ![]u8 {
    const len = (hex.len + 1) / 2;
    const out = buf[0..len];
    if (hex.len % 2 == 1) {
        out[0] = try std.fmt.parseInt(u8, hex[0..1], 16);
        _ = try std.fmt.hexToBytes(out[1..], hex[1..]);
    } else {
        _ = try std.fmt.hexToBytes(out, hex);
    }
    return out;
}

fn runFac(tainted: bool) !void {
    const vectors = @import("tsslib_vectors.zig");
    const pp = vectors.tsslib_keygen.parties[0];
    const vp = vectors.tsslib_keygen.parties[1];
    var p: [128]u8 = undefined;
    var q: [128]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p, pp.paillier_p);
    _ = try std.fmt.hexToBytes(&q, pp.paillier_q);
    var key = try root.paillierBlumFromPrimes(&p, &q);
    defer key.wipe();
    const n0 = key.modulus();
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    const nt = try root.AuxModulus.fromBytes(try unhexInto(&buf, vp.n_tilde), .big);
    const h1 = try root.AuxFe.fromBytes(nt, try unhexInto(&buf, vp.h1), .big);
    const h2 = try root.AuxFe.fromBytes(nt, try unhexInto(&buf, vp.h2), .big);

    if (tainted) {
        std.valgrind.memcheck.makeMemUndefined(&p);
        std.valgrind.memcheck.makeMemUndefined(&q);
    }
    var prng = std.Random.DefaultPrng.init(0x6661_6370_726f_7665); // "facprove"
    const proof = try root.fac_proof.prove(n0, &p, &q, .{ .n_tilde = nt, .h1 = h1, .h2 = h2 }, "ctgrind", prng.random());
    std.debug.print("z1={x} z2={x} v={x}\n", .{ proof.z1.bytes(), proof.z2.bytes(), proof.v.bytes() });
}

// ── the harness proper ────────────────────────────────────────────────────

// ── target "pimod": taint the Paillier factors through Πmod's prover ─────
//
// `aux_proofs.Pimod.provePaillier` over tss-lib's 2048-bit N, `p`/`q`
// tainted. Since 2026-10-02 the per-round work (Legendre symbols, 4th roots,
// CRT, q⁻¹ mod p) runs on montint.DynModint modulo the secret primes; what
// stays variable-time is the big-integer setup (φ, d = Ñ⁻¹ mod φ by extended
// Euclid) — the classified residue in the tsv.
fn runPimod(allocator: std.mem.Allocator, tainted: bool) !void {
    const vectors = @import("tsslib_vectors.zig");
    const pp = vectors.tsslib_keygen.parties[0];
    var p: [128]u8 = undefined;
    var q: [128]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p, pp.paillier_p);
    _ = try std.fmt.hexToBytes(&q, pp.paillier_q);
    var key = try root.paillierBlumFromPrimes(&p, &q);
    defer key.wipe();
    const n0 = key.modulus();
    if (tainted) {
        std.valgrind.memcheck.makeMemUndefined(&p);
        std.valgrind.memcheck.makeMemUndefined(&q);
    }
    var prng = std.Random.DefaultPrng.init(0x7069_6d6f_64); // "pimod"
    const proof = try root.aux_proofs.Pimod.provePaillier(allocator, n0, &p, &q, "ctgrind", prng.random());
    var xb: [root.aux_modulus_bytes]u8 = undefined;
    try proof.entries[0].x.toBytes(&xb, .big);
    std.debug.print("x0={x}\n", .{xb});
}

// ── target "piprm": taint the ring-Pedersen trapdoor through Πprm's prover ─
//
// `aux_proofs.Piprm.proveBound` over tss-lib's 2048-bit Ñ, `p̃`, `q̃` and
// `λ` tainted (tss-lib's α = log_h1 h2, not this module's log_h2 h1: the
// proof it yields does not verify, and the timing does not care). Since 2026-10-03 φ is a limb product and the
// responses `a_i + e_i·λ mod φ` one masked subtraction; what branches is the
// nonce draw's accept verdict (`a_i < φ`).
fn runPiprm(allocator: std.mem.Allocator, tainted: bool) !void {
    const vectors = @import("tsslib_vectors.zig");
    const pp = vectors.tsslib_keygen.parties[0];
    var nt_b: [256]u8 = undefined;
    var h1_b: [256]u8 = undefined;
    var h2_b: [256]u8 = undefined;
    var lam_b: [256]u8 = undefined;
    var p: [128]u8 = undefined;
    var q: [128]u8 = undefined;
    const nt_s = try std.fmt.hexToBytes(&nt_b, pp.n_tilde);
    const h1_s = try std.fmt.hexToBytes(&h1_b, pp.h1);
    const h2_s = try std.fmt.hexToBytes(&h2_b, pp.h2);
    const lam_s = try std.fmt.hexToBytes(&lam_b, pp.aux_lambda);
    _ = try std.fmt.hexToBytes(&p, pp.aux_p_safe);
    _ = try std.fmt.hexToBytes(&q, pp.aux_q_safe);
    const nt = try root.AuxModulus.fromBytes(nt_s, .big);
    const aux: root.AuxParams = .{
        .n_tilde = nt,
        .h1 = try root.AuxFe.fromBytes(nt, h1_s, .big),
        .h2 = try root.AuxFe.fromBytes(nt, h2_s, .big),
    };
    var trapdoor: root.AuxTrapdoor = .{
        .p = &p,
        .q = &q,
        .lambda = try root.AuxFe.fromBytes(nt, lam_s, .big),
    };
    if (tainted) {
        std.valgrind.memcheck.makeMemUndefined(&p);
        std.valgrind.memcheck.makeMemUndefined(&q);
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&trapdoor.lambda.v.limbs_buffer));
    }
    std.mem.doNotOptimizeAway(&trapdoor);
    var prng = std.Random.DefaultPrng.init(0x7069_7072_6d); // "piprm"
    const proof = try root.aux_proofs.Piprm.proveBound(allocator, aux, trapdoor, "ctgrind", prng.random());
    // XOR of every z_i: the rounds with e_i = 1 carry λ's taint (z_i = a_i
    // alone when e_i = 0, untainted), so one fold is the witness for all.
    var acc = [_]u8{0} ** root.aux_modulus_bytes;
    for (proof.entries) |entry| {
        var zb: [root.aux_modulus_bytes]u8 = undefined;
        try entry.z.toBytes(&zb, .big);
        for (&acc, zb) |*a, b| a.* ^= b;
    }
    std.debug.print("zfold={x}\n", .{acc});
}

// ── target "prime": Miller-Rabin on a secret prime ──────────────────────
//
// `root.isProbablePrime` on tss-lib's 1024-bit Blum prime `p`, tainted —
// the path every accepted candidate of the prime searches takes.
fn runPrime(tainted: bool) !void {
    const vectors = @import("tsslib_vectors.zig");
    var p: [128]u8 = undefined;
    _ = try std.fmt.hexToBytes(&p, vectors.tsslib_keygen.parties[0].paillier_p);
    var m = try root.AuxModulus.fromBytes(&p, .big);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&m.v.limbs_buffer));
    std.mem.doNotOptimizeAway(&m);
    var prng = std.Random.DefaultPrng.init(0x7072_696d_65); // "prime"
    const verdict = root.isProbablePrime(m, 1024, prng.random());
    // The verdict on a prime's path is a constant (every round passes), so
    // it carries no taint; print the tainted input too, as the witness that
    // the taint was live when the test ran.
    std.debug.print("prime={} ctgrind_result={x}\n", .{ verdict, std.mem.asBytes(&m.v.limbs_buffer)[0..16] });
}

const Target = enum { share, nonce, betaprime, fac, pimod, piprm, prime };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "share")) return .share;
    if (std.mem.eql(u8, s, "nonce")) return .nonce;
    if (std.mem.eql(u8, s, "betaprime")) return .betaprime;
    if (std.mem.eql(u8, s, "fac")) return .fac;
    if (std.mem.eql(u8, s, "pimod")) return .pimod;
    if (std.mem.eql(u8, s, "piprm")) return .piprm;
    if (std.mem.eql(u8, s, "prime")) return .prime;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn printOutcome(result: anyerror!signing.Signature) void {
    if (result) |sig| {
        std.debug.print("r={x} s={x}\n", .{ sig.r, sig.s });
    } else |err| {
        // Formatted regardless of taint state: still the propagation
        // witness (reaching this branch after a tainted run is itself
        // informative, and `{t}` touches std's error-name formatter).
        std.debug.print("aborted: {t}\n", .{err});
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var da: std.heap.DebugAllocator(.{}) = .init; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    defer _ = da.deinit();
    const allocator = da.allocator();

    if (target == .fac) return runFac(tainted);
    if (target == .pimod) return runPimod(allocator, tainted);
    if (target == .piprm) return runPiprm(allocator, tainted);
    if (target == .prime) return runPrime(tainted);

    // Fixture setup randomness is ALWAYS real — Phase 2a keygen is not
    // measured here (see buildFixture's doc comment).
    var setup_prng = std.Random.DefaultPrng.init(0x746872_65735f65); // "thres_e"
    const setup_random = setup_prng.random();

    const fixture = try buildFixture(allocator, setup_random);
    defer fixture.deinit(allocator);

    const message = "ctgrind harness message — threshold_ecdsa presign";
    const t = fixture.key_shares.len;
    var prngs = [2]std.Random.DefaultPrng{ .init(0x7061_7274_7931), .init(0x7061_7274_7932) }; // "party1", "party2"

    switch (target) {
        .share => {
            if (tainted) {
                for (fixture.key_shares) |*ks| {
                    std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&ks.secret_share));
                }
            }
            const randoms = [2]std.Random{ prngs[0].random(), prngs[1].random() };
            printOutcome(runProtocol(allocator, fixture.key_shares, &randoms, message));
        },
        .nonce => {
            var wrappers = [2]TaintScalars{
                .{ .inner = prngs[0].random(), .taint = tainted },
                .{ .inner = prngs[1].random(), .taint = tainted },
            };
            const randoms = [2]std.Random{ wrappers[0].random(), wrappers[1].random() };
            printOutcome(runProtocol(allocator, fixture.key_shares, &randoms, message));
            // Printed in both builds: a `taint=no` run must report the same
            // count, a cross-check between the two.
            std.debug.print("draws_48b={d}\n", .{wrappers[0].draws + wrappers[1].draws});
        },
        .betaprime => {
            var wrappers = [2]TaintBetaPrime{
                .{ .inner = prngs[0].random(), .taint = tainted },
                .{ .inner = prngs[1].random(), .taint = tainted },
            };
            const randoms = [2]std.Random{ wrappers[0].random(), wrappers[1].random() };
            const result = runProtocol(allocator, fixture.key_shares, &randoms, message);
            // Checked BEFORE the result is printed: a stale width assumption
            // must leave the output pin with nothing to read, not a row that
            // measured an untainted run.
            const draws = wrappers[0].draws + wrappers[1].draws;
            if (draws != 2 * t * (t - 1)) {
                std.debug.print("draws_160b={d}, expected {d}\n", .{ draws, 2 * t * (t - 1) });
                return error.HarnessBetaPrimeDrawCount;
            }
            printOutcome(result);
            std.debug.print("draws_160b={d}\n", .{draws});
        },
        .fac, .pimod, .piprm, .prime => unreachable, // returned above
    }
}
