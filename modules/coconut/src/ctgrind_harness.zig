// SPDX-License-Identifier: MIT

//! ctgrind_harness — constant-time measurement for `coconut`, a program
//! run through valgrind/memcheck rather than a `zig build test-coconut`
//! assertion (memcheck's context count is valgrind's own verdict, not
//! something a Zig test can observe). Build/run per
//! `../../../scripts/checks/ctgrind.sh`'s header (once the coordinator adds the
//! `TARGETS`/`MODES`/`PATTERN`/`LABEL` entries suggested at the bottom of
//! this file — that script REFUSES an unlisted module rather than
//! silently skipping it):
//!
//!     zig build ctgrind -Dctgrind-module=coconut -Dctgrind-valgrind=true  -Doptimize=ReleaseFast
//!     zig build ctgrind -Dctgrind-module=coconut -Dctgrind-valgrind=false -Doptimize=ReleaseFast
//!     valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!         zig-out/ctgrind/ctgrind-coconut <target> <yes|no>
//!
//! Usage: ctgrind-coconut <target> <yes|no>
//!   targets: authority_sign | user_issue | user_show
//!
//! ## Existing constant-time claim: NONE
//!
//! `SPEC.md`'s only hit for "constant" is unrelated ("the curve generators
//! `g1`, `g2` (constants)" in §1 Setup). `README.md` makes no
//! constant-time statement either. Unlike `bls12_381`/`ct25519`/etc, this
//! module's docs assert NOTHING about branch-freedom for the authority's
//! key material or the user's attributes/blinding — there is no sentence
//! here for this file to be evidence FOR. This harness is measurement
//! without a pre-existing predicate, and it does not add one: no claim is
//! inserted into `SPEC.md`/`README.md` as a side effect of writing it.
//!
//! ## Two parties, two secrets, three targets
//!
//! Coconut is a THRESHOLD scheme: the authorities' key shares and the
//! user's attributes are secret to different parties and enter the
//! protocol at different call sites. Conflating them into one target would
//! blur exactly the distinction the scheme is built to keep.
//!
//! * `authority_sign` — an AUTHORITY's Shamir key share `(x(j), y_i(j))`
//!   entering `signPartial` (`credential.zig`), the §4.2 `Sign` step. This
//!   harness starts AT the point the share already exists (an established
//!   authority key), matching every real `signPartial` call site — there
//!   is no `keys.keygenFrom` dealer step to taint here. The attribute
//!   vector passed alongside it is left PUBLIC/untainted: blind issuance
//!   (ElGamal blinding + NIZK π_s, `SPEC.md`'s "deferred increments") does
//!   not exist yet in this module, so in the CURRENT implementation the
//!   attributes genuinely do reach the authority in the clear — tainting
//!   them here would be evidence for a threat model this code does not yet
//!   implement.
//! * `user_issue` — the USER's own private attribute vector `m_1..m_q`
//!   entering `Parameters.commonBase` (`params.zig`), i.e. the commitment
//!   `cm = Σ [m_i] h_i` the user computes LOCALLY before ever contacting an
//!   authority, and the subsequent `hashToCurveG1(cm)` that turns it into
//!   the shared signing base `h`. This is "the user's private attributes
//!   entering credential issuance": the one issuance-side step where the
//!   attribute VALUES drive a secret-dependent scalar multiplication
//!   before anything crosses a wire.
//! * `user_show` — the USER's full attribute vector (ALL `q`, not just the
//!   hidden ones — `kappaPlain` folds every attribute in regardless of
//!   disclosure) PLUS the re-randomisation/blinding scalars `r'`, `r` and
//!   the Sigma-protocol witnesses `r̃`, `m̃_j` entering `proveCredential`
//!   (`credential.zig`'s §4.2 `ProveCred`), the selective-disclosure show.
//!   This is where hiding actually matters: a verifier watching the show
//!   must learn nothing about the HIDDEN attributes or the blinding beyond
//!   what the disclosed values and the proof's validity already reveal
//!   (`credential.zig`'s own doc comment on the two-transcript extraction
//!   risk if the blinding stream ever repeats — the same property a timing
//!   leak would defeat by a different route).
//!
//! ## Two taint techniques, and why they differ
//!
//! `secretFr` (below) is the `bls12_381` harness's own "parse clean, taint
//! the RESULT" shape: derive deterministic bytes, force the top byte to 0
//! (`Fr`'s modulus `r` has top byte `0x73` — see `scalar.zig`'s `r_bytes`
//! — so a top byte of 0 is unconditionally `< r`, the same trick
//! `bls12_381/src/ctgrind_harness.zig`'s `secretFp`/`secretFr` use),
//! `Fr.fromBytes` it UNTAINTED, then `makeMemUndefined` the resulting `Fr`.
//! That keeps `fromBytes`'s own parse-path canonicality check OUT of the
//! tainted dataflow, because for `authority_sign`'s key share and
//! `user_issue`/`user_show`'s attribute vectors this harness constructs
//! the `Fr` itself — there is no "wire decode" step whose validation
//! branch would otherwise get blamed on the VALUE.
//!
//! `TaintedRandom` (below) cannot use that shape. `proveCredential`'s
//! blinding scalars are drawn INSIDE `credential.zig` via
//! `keys.Entropy.scalar` → `Fr.fromBytes`, a call site this harness does
//! not own — there is no outside hook to taint the parsed `Fr` after the
//! fact. So `TaintedRandom.fill` taints the RAW BYTES at the point of
//! generation instead (still forcing the top byte to 0 for the same
//! canonicality reason, so `Entropy.scalar`'s rejection-sampling loop in
//! `keys.zig` never retries — a retry would be its own tainted-comparison
//! branch, attributed to `keys.zig`, muddying the very count this file
//! exists to attribute cleanly). This is also the MORE faithful model for
//! what it measures: `r'`/`r`/`r̃`/`m̃_j` are freshly-drawn secret
//! randomness, not a decode of a publicly-shaped wire value, so the byte
//! source itself genuinely is the secret. Documented consequence: unlike
//! the `secretFr` targets, `user_show`'s blinding draws put
//! `Fr.fromBytes`'s OWN parse-path canonicality check in-scope for taint —
//! see the substrate note below, which is exactly that check.
//!
//! ## Substrate inherited from `bls12_381` (read before re-deriving this)
//!
//! Round-2/3 measurements of `bls12_381` and its consumers found:
//!
//! * `std.crypto.ff` branches at `ff.zig:150` (`Uint.toBytes` overflow
//!   check — every `scalarMul` converts the secret scalar to bytes for the
//!   ladder), `:267`/`:532`/`:535` (`reduce`/`shiftIn`/`cmov`), and `:345`
//!   (parse-side canonicality — see `TaintedRandom` above for why
//!   `user_show` puts this one specifically in-scope while the other two
//!   targets do not).
//! * `Fp2.isZero` is `c0.isZero() and c1.isZero()` — Zig's `and`
//!   SHORT-CIRCUITS, a real branch on secret limbs upstream of `g2.zig`'s
//!   otherwise branchless `ctSelect` point addition. Relevant to
//!   `user_show` (its `kappa`/`Aw` accumulation is `G2`) and irrelevant to
//!   `authority_sign`/`user_issue` (both pure `G1`).
//! * `bls12_381/SPEC.md:387` and `bls_sig.zig:48` both claim "no
//!   secret-dependent branches"; the measurement disagrees. This module's
//!   own docs make NO such claim (see above), so there is nothing here for
//!   that specific disagreement to contradict — but the underlying
//!   branches are still live in every target below that touches `G2`
//!   (`user_show`) or converts a secret scalar to bytes (all three).
//!
//! This file reports its own contexts split into coconut-own
//! (`credential.zig`/`params.zig`) versus this inherited substrate
//! (`bls12_381`'s files, and std's `ff.zig` beneath `scalar.zig`) rather
//! than one merged number — see the run report, not this doc comment, for
//! the actual counts.
//!
//! ## The propagation proof and the two traps
//!
//! Same two traps as every other harness in this collection (see
//! `ct25519`'s doc comment for the long version): (1)
//! `std.valgrind.doClientRequest` is a no-op unless built `-fvalgrind`,
//! which release modes do not default on — the no-`-fvalgrind` "trap" row
//! exists so a silent-clean run cannot be mistaken for a proven-clean one;
//! (2) an optimizer could in principle keep a defined copy of a tainted
//! value around — `reloadVolatile` forces one real load from freshly
//! tainted memory immediately before the call under test, defensive
//! (unproven) insurance, not a demonstrated requirement on today's
//! compiler, exactly as `ct25519`'s doc comment states for its own use of
//! the same helper. And after each target's call under test, this harness
//! formats its result through `std.debug.print` (not constant-time by
//! design) as the propagation witness: a zero count inside the target's
//! own files means "no branch found" only if the witness for that same
//! run is nonzero, i.e. the taint demonstrably reached somewhere
//! observable.
//!
//! ## ReleaseFast only
//!
//! Same reasoning as `bls12_381`'s harness: Debug/ReleaseSafe turn plain
//! `+`/`-`/`*` on scalar-width integers into overflow-check branches that
//! have nothing to do with this module's arithmetic and would flood the
//! report (`ct25519` measured 89 956 errors from 1000 contexts at
//! ReleaseSafe — valgrind's own `--error-limit` cutoff). Not measured at
//! Debug at all: Zig 0.16's self-hosted x86_64 backend is Debug's default
//! and cannot be read by valgrind's DWARF parser (`scripts/checks/ctgrind.sh`'s
//! own header measured 42.4% of frames unresolved, 51/60 of the resolved
//! ones on the WRONG line) — a property of the backend, not of this
//! module's code.

const std = @import("std");
const builtin = @import("builtin");
const coconut = @import("root.zig");
const bls = @import("bls12_381");

const Fr = bls.Fr;

/// A PUBLIC test scalar (small integer, big-endian) — for values this
/// harness deliberately does NOT taint (the plain attribute vector at
/// `authority_sign`'s call site, the scaffold key/attributes `user_show`
/// uses only to produce a valid `Credential` to re-randomise). Mirrors
/// `credential.zig`'s own `frOf` test helper.
fn frOf(v: u64) Fr {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, buf[24..32], v, .big);
    return Fr.fromBytes(buf) catch unreachable;
}

/// Deterministic "random" bytes, computed at RUNTIME (not folded at
/// comptime, so tainting them marks memory the code under test actually
/// reads) — SHAKE256 over a domain tag and a runtime `salt` (so a family
/// of independent secret scalars, e.g. one per Shamir-share component or
/// per attribute index, can share one comptime domain string). Not a KAT
/// — a diagnostic input, not a correctness one.
fn secretBytes(comptime n: usize, comptime domain: []const u8, salt: u64) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    var sbuf: [8]u8 = undefined;
    std.mem.writeInt(u64, &sbuf, salt, .little);
    st.update(&sbuf);
    st.squeeze(&out);
    return out;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the code under test cannot be fed a copy that predates
/// `makeMemUndefined` — see the module doc comment's "propagation proof
/// and the two traps" section.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// A tainted `Fr` scalar — "parse clean, taint the result" (see the module
/// doc comment's "Two taint techniques" section for why this shape is
/// right for `authority_sign`/`user_issue`/`user_show`'s ATTRIBUTE and
/// KEY-SHARE scalars, but not for `user_show`'s internally-drawn blinding
/// — that one uses `TaintedRandom` instead). `r[0] = 0` makes the draw
/// canonical without a comparison: `Fr`'s modulus top byte is `0x73`
/// (`scalar.zig`'s `r_bytes`), so any 32-byte value whose top byte is `0`
/// is unconditionally `< r` — the same trick `bls12_381`'s own harness
/// uses for exactly this type.
fn secretFr(comptime domain: []const u8, salt: u64, tainted: bool) !Fr {
    const raw = secretBytes(Fr.encoded_bytes, domain, salt);
    var r = reloadVolatile(Fr.encoded_bytes, &raw);
    r[0] = 0;
    var v = try Fr.fromBytes(r);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&v));
    return v;
}

/// A `std.Random` that hands `proveCredentialSeededForTest` a fresh
/// deterministic 32-byte draw per call, canonicalised the same way
/// `secretFr` is (top byte forced to 0), and — when `tainted` — marks that
/// buffer UNDEFINED before returning from `fill`. See the module doc
/// comment's "Two taint techniques" section for why this taints the RAW
/// BYTES at the point of generation rather than the parsed `Fr`
/// afterward: `proveCredential`'s re-randomisation/witness scalars are
/// drawn *inside* `credential.zig` via `Entropy.scalar` → `Fr.fromBytes`,
/// a call site this harness does not own.
const TaintedRandom = struct {
    domain: []const u8,
    tainted: bool,
    counter: u64 = 0,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *TaintedRandom = @ptrCast(@alignCast(ptr));
        var st = std.crypto.hash.sha3.Shake256.init(.{});
        st.update(self.domain);
        var cbuf: [8]u8 = undefined;
        std.mem.writeInt(u64, &cbuf, self.counter, .little);
        self.counter += 1;
        st.update(&cbuf);
        st.squeeze(buf);
        // Same canonicalisation as `secretFr`, and load-bearing here for
        // the same reason: without it, `Entropy.scalar`'s rejection loop
        // (`keys.zig`) could retry on a tainted comparison, attributing an
        // extra branch to `keys.zig` that has nothing to do with the
        // scalar's VALUE.
        if (buf.len == Fr.encoded_bytes) buf[0] = 0;
        if (self.tainted) std.valgrind.memcheck.makeMemUndefined(buf);
    }

    fn random(self: *TaintedRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

/// `authority_sign`: an authority's Shamir key share entering `signPartial`
/// (§4.2 `Sign`). TAINTED: `x(j)`, `y_1(j)..y_q(j)`. PUBLIC: the attribute
/// vector and the common base `h` (blind issuance is not implemented yet —
/// see the module doc comment).
fn runAuthoritySign(allocator: std.mem.Allocator, tainted: bool) !void {
    const q = 3;
    const p = try coconut.params.Parameters.generate(allocator, q);
    defer p.deinit(allocator);

    const attrs = [_]Fr{ frOf(11), frOf(22), frOf(33) };
    const h = p.commonBase(&attrs);

    var ys: [q]Fr = undefined;
    for (&ys, 0..) |*y, i| y.* = try secretFr("ctgrind-coconut-authority-y-v1", @as(u64, i), tainted);
    const x = try secretFr("ctgrind-coconut-authority-x-v1", 0, tainted);

    // Not `.deinit()`-ed: `ys` is a stack array, not allocator-owned —
    // `SecretKeyShare.deinit` would `allocator.free` a slice it never
    // `allocator.alloc`-ed. This harness is a one-shot diagnostic process
    // (the same reason `ct25519`/`bls12_381`'s harnesses do not scrub
    // their secrets either); production callers still own that contract.
    const share = coconut.SecretKeyShare{ .index = 1, .x = x, .ys = &ys };
    const partial = try coconut.signPartial(share, h, &attrs);

    std.debug.print("partial.s={x}\n", .{bls.g1.toBytesCompressed(partial.s)});
}

/// `user_issue`: the user's own attribute vector entering
/// `Parameters.commonBase` (§4.1 `Setup`'s commitment, computed locally
/// before contacting any authority). TAINTED: `m_1..m_q`.
fn runUserIssue(allocator: std.mem.Allocator, tainted: bool) !void {
    const q = 4;
    const p = try coconut.params.Parameters.generate(allocator, q);
    defer p.deinit(allocator);

    var attrs: [q]Fr = undefined;
    for (&attrs, 0..) |*m, i| m.* = try secretFr("ctgrind-coconut-user-issue-attr-v1", @as(u64, i), tainted);

    const h = p.commonBase(&attrs);
    std.debug.print("h={x}\n", .{bls.g1.toBytesCompressed(h)});
}

/// `user_show`: the user's full attribute vector plus the
/// re-randomisation/blinding scalars entering `proveCredential` (§4.2
/// `ProveCred`, the selective-disclosure show). TAINTED: `m_1..m_q`
/// (`disclosed` in the clear — a public boolean mask does not change which
/// scalars matter, but tainting an actual `bool` gates a branch on itself,
/// so it stays untainted like the attribute COUNT does elsewhere in this
/// collection) and `r'`, `r`, `r̃`, `m̃_j` via `TaintedRandom`. UNTAINTED
/// scaffolding: the authority key and the plain attribute vector used only
/// to mint a valid `Credential` — `proveCredential` re-derives `kappa`/`nu`
/// from the `attrs` argument independently, so it never checks that this
/// scaffold matches, and it is not part of the claim this target measures.
fn runUserShow(allocator: std.mem.Allocator, tainted: bool) !void {
    const q = 4;
    const p = try coconut.params.Parameters.generate(allocator, q);
    defer p.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(0xC0C0_C0C0);
    var kk = try coconut.keygenSeededForTest(allocator, prng.random(), q, 2, 3);
    defer kk.deinit(allocator);
    const setup_attrs = [_]Fr{ frOf(1), frOf(2), frOf(3), frOf(4) };
    const setup_h = p.commonBase(&setup_attrs);
    const cred = coconut.psSignWithSecret(kk.master_sk, setup_h, &setup_attrs);

    var attrs: [q]Fr = undefined;
    for (&attrs, 0..) |*m, i| m.* = try secretFr("ctgrind-coconut-user-show-attr-v1", @as(u64, i), tainted);
    // 2 disclosed, 2 hidden — exercises both the `if (d) continue` and the
    // `if (!d) continue` arms in `proveCredential`'s per-attribute loops.
    const disclosed = [_]bool{ true, false, true, false };

    var rnd = TaintedRandom{ .domain = "ctgrind-coconut-user-show-blinding-v1", .tainted = tainted };
    const proof = try coconut.proveCredentialSeededForTest(allocator, rnd.random(), p, kk.master_vk, cred, &attrs, &disclosed);
    defer proof.deinit(allocator);

    std.debug.print("sigma1={x}\n", .{bls.g1.toBytesCompressed(proof.sigma1)});
    std.debug.print("kappa={x}\n", .{bls.g2.toBytesCompressed(proof.kappa)});
    std.debug.print("challenge={x}\n", .{proof.challenge.toBytes()});
    std.debug.print("response_r={x}\n", .{proof.response_r.toBytes()});
    for (proof.responses_m, 0..) |m, i| std.debug.print("responses_m[{d}]={x}\n", .{ i, m.toBytes() });
}

const Target = enum { authority_sign, user_issue, user_show };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "authority_sign")) return .authority_sign;
    if (std.mem.eql(u8, s, "user_issue")) return .user_issue;
    if (std.mem.eql(u8, s, "user_show")) return .user_show;
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
    const taint = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    const allocator = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    switch (target) {
        .authority_sign => try runAuthoritySign(allocator, taint),
        .user_issue => try runUserIssue(allocator, taint),
        .user_show => try runUserShow(allocator, taint),
    }
}

// ── suggested scripts/checks/ctgrind.sh config (coordinator: paste in, do not
// generate mechanically — every existing entry carries hand-written
// reasoning in its own comment; these follow the same shape) ─────────────
//
// declare -A TARGETS=(
//     [coconut]="authority_sign user_issue user_show"
// )
// declare -A MODES=(
//     [coconut]="ReleaseFast"
// )
// declare -A PATTERN=(
//     # The authority's Shamir share -> signingExponent (Fr add/mul) ->
//     # G1 scalarMul. `credential.zig` is coconut's own file; the rest is
//     # the bls12_381 substrate every target here shares.
//     [coconut/authority_sign]='credential[.]zig|g1[.]zig|fp[.]zig|scalar[.]zig'
//     # The user's local commitment cm = Sum [m_i] h_i (G1 scalarMul) then
//     # hashToCurveG1(cm) -> h. `params.zig` is coconut's own file;
//     # hash_to_curve.zig is bls12_381's SSWU map, now running on a
//     # SECRET-derived input for the first time in this repo (every other
//     # consumer's hash-to-curve input is public -- see this file's module
//     # doc comment).
//     [coconut/user_issue]='params[.]zig|g1[.]zig|fp[.]zig|scalar[.]zig|hash_to_curve[.]zig'
//     # kappaPlain (G2 scalarMul over ALL attributes), the re-randomisation
//     # (G1 scalarMul by r'), and the Sigma-protocol commitments/responses
//     # (G2 + Fr arithmetic). `credential.zig` is coconut's own file.
//     [coconut/user_show]='credential[.]zig|g1[.]zig|g2[.]zig|fp[.]zig|fp2[.]zig|scalar[.]zig'
// )
// declare -A LABEL=(
//     [coconut/authority_sign]='coconut signPartial (authority share)'
//     [coconut/user_issue]='coconut commonBase (user attrs -> h)'
//     [coconut/user_show]='coconut proveCredential (user attrs+blinding)'
// )
