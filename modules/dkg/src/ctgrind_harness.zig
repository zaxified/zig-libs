// SPDX-License-Identifier: MIT

//! ctgrind_harness — this module's `SPEC.md`/`README.md` make NO
//! const-time claim at all (checked directly: neither file contains the
//! words "constant-time"/"const-time"/"timing"/"side-channel" anywhere).
//! This file exists anyway, for the same reason `threshold_ecdsa`'s
//! harness does: `dkg` is the dealer-free GJKR replacement for
//! `threshold_ecdsa.keygenTrustedDealer`, its whole job is generating a
//! long-term ECDSA secret share with no dealer ever seeing it, and it
//! shares `threshold_ecdsa`'s curve backend (`std.crypto.ecc.Secp256k1`)
//! and much of its shape (`commit.zig`'s Pedersen/Feldman evaluation is a
//! direct port of `threshold_ecdsa`'s `evalPolynomialAt`/
//! `derivePublicKeyShare`). Nobody had measured whether that backend's own
//! secret-dependent `rejectIdentity` branch, or anything in this module's
//! OWN code, shows up when driven with this module's actual secret
//! material. This file settles that with numbers, not adds a claim nobody
//! asked for — see the "What SPEC.md/README.md say" section at the bottom
//! before reading anything here as evidence of a promise this module
//! makes.
//!
//! Run via `zig build ctgrind -Dctgrind-module=dkg -Dctgrind-valgrind=true
//! -Doptimize=ReleaseFast` (`-Dctgrind-valgrind=false` for the trap row),
//! then `valgrind --tool=memcheck --error-exitcode=99 --num-callers=20
//! zig-out/ctgrind/ctgrind-dkg <target> <taint>`. NOT wired into `zig
//! build test-dkg` — memcheck's context count is valgrind's own verdict,
//! not something a Zig test can assert on. `zig build check-ctgrind`
//! compiles this (Debug, `-fvalgrind` forced on) as a rot guard only, not
//! a measurement — see `scripts/ctgrind.sh`'s own header for why Debug is
//! unmeasurable here (self-hosted backend, broken `.debug_line`).
//!
//! ## What is tainted, entering which public function
//!
//! **`coeffs`** — every 48-byte draw `random.bytes()` produces during a
//! REAL, honest `Dkg.run(allocator, cfg, .{}, random)` (the module's own
//! top-level entry point; `Corruption{}` means no scripted Byzantine
//! deviation). `deal()` (`protocol.zig`) is the ONLY place `Dkg.run` ever
//! reads `random`: one 48-byte `randomScalar` draw per Pedersen-VSS
//! coefficient — `a[0..t]` then `b[0..t]`, per dealer, `n` dealers, `2·n·t`
//! draws total (12 for this harness's `t=2,n=3`) — and NOTHING else in the
//! honest driver ever touches `random` again: QUAL, both verification
//! equations, and the final combine are all deterministic given the dealt
//! shares. So tainting every 48-byte draw here is tainting exactly "each
//! party's secret polynomial coefficients" (`f_i`/`f'_i`'s coefficients,
//! GJKR's `a_ik`/`b_ik`) — there is no OTHER randomness to exclude by a
//! budget the way `threshold_ecdsa`'s per-signature-nonce target needs.
//! The point-to-point shares "it computes for the others"
//! (`wire_s[d][r]`/`wire_sp[d][r]`, `commit.evalPoly` Horner evaluations of
//! these SAME tainted coefficients) are downstream of this taint by
//! construction, not separately marked — evaluating a tainted polynomial
//! at a public point does not untaint the result. This target exercises,
//! in call order: `commit.pedersenCommitVector`/`feldmanCommitVector`
//! (`g^{a_ik}`/`g^{a_ik}·h^{b_ik}`, secret-scalar `basePoint.mul` and
//! `.mul` on the Pedersen `h` point), `commit.evalPoly` (Horner, secret
//! `Scalar.mul`/`.add`), `core.verifyPedersenShare`/`verifyFeldmanShare`
//! (`commit.pedersenEvalShare`/`feldmanEvalShare`+`evalCommitmentAt`, MORE
//! secret-scalar curve `mul`s — the received share `s`/`s'` themselves,
//! not just the coefficients), `core.combineKeyShare` (`x_j = Σ s_ij`,
//! plain `Scalar.add`), and finally `Secp256k1.basePoint.mul(x_j...)`
//! inside `Dkg.run` itself (`protocol.zig:234`) to derive
//! `DkgShareOutput.verifying_share` — the SAME disputed
//! `basePoint.mul`/`rejectIdentity` shape round 2's `threshold_ecdsa`
//! harness measured and settled (see below). `qualified`/the Feldman
//! commitment vectors `A`/Pedersen vectors `C` are NEVER tainted — they
//! are exactly the public broadcast material GJKR's whole bias-prevention
//! argument depends on being public, per this task's own instruction.
//!
//! **`combine`** — isolates CORE 5 (`combineKeyShare`, "this party's final
//! secret share", `x_j = Σ_{i∈QUAL} s_ij`) on its own, decoupled from the
//! rest of the protocol. Three REAL scalars (drawn from a real, always-real
//! PRNG — standing in for three already-ACCEPTED per-dealer shares; their
//! numeric origin is irrelevant to `combineKeyShare`'s contract, which is
//! "sum the qualified entries") are placed into the exact `[]const
//! ?Scalar` array shape `Dkg.run` itself builds (`received`,
//! `protocol.zig:224`), then the WHOLE array's storage is marked
//! undefined via `std.valgrind.memcheck.makeMemUndefined` in one call —
//! same idiom as `threshold_ecdsa`'s `share` target tainting
//! `ks.secret_share` directly on an already-built value right before the
//! real API call, not through a private helper — immediately before
//! calling the module's own PUBLIC `combineKeyShare(qualified, received)`
//! (`root.combineKeyShare`, re-exported from `core.zig`). `qualified =
//! .{true,true,true}` stays real (it is public protocol state, not a
//! secret, per the same "don't taint public material" instruction). The
//! returned `x_j` — "the final combined secret share" — is then driven
//! through `Secp256k1.basePoint.mul(x_j.toBytes(.big), .big)`, the exact
//! call `checks.verifyingShareConsistent`/`reconstructsToQ` and
//! `Dkg.run` itself make with this value, so this target measures the
//! SAME disputed line as `coeffs` but with the combine step isolated from
//! everything upstream of it.
//!
//! ## A disputed claim round 2 already settled — do not re-derive it
//!
//! `threshold_ecdsa`'s own harness (round 2, 2026-09-09) measured and
//! closed a triage claim that routing a secret-scalar `basePoint.mul`
//! through `k256` instead of `std.crypto.ecc.Secp256k1` would remove a
//! branch: it does not, because `k256`'s own `Secp256k1.mul`/`combMulBase`
//! (`modules/k256/src/group.zig:278`, `:347`) end in `try
//! q.rejectIdentity()` too — the exact same one-bit "did the ladder land
//! on the group identity" check `std.crypto.ecc.Secp256k1.mul` performs
//! internally (`lib/std/crypto/pcurves/secp256k1.zig`, `pcMul16`). `dkg`
//! does not even raise the question here: `commit.zig`/`core.zig`/
//! `protocol.zig` all call `Secp256k1.basePoint.mul`/`.mul` directly via
//! `tecdsa.Secp256k1 = std.crypto.ecc.Secp256k1` (`threshold_ecdsa/root.zig`
//! line 141) — this module never touches `k256` at all (it is not even in
//! `dkg`'s `meta.deps`). Any context this harness attributes to std's
//! secp256k1 ladder ending in `rejectIdentity` is that SAME accepted
//! ~2^-256 class, not a new defect — reported as such below, not as a
//! fresh finding.
//!
//! ## What six-plus rounds have established, applied here
//!
//! Branchless source does not settle anything — LLVM's ReleaseFast
//! codegen choice is unpredictable and has gone both ways across this
//! repository's own modules — so every address this file's report
//! classifies as "in-file" was disassembled, not inferred from reading
//! `commit.zig`/`core.zig`/`protocol.zig`'s source. Three classes are in
//! play: **class 1** branches on a secret byte (a real defect); **class
//! 2** branches on a value the protocol discloses anyway (`Q`,
//! `verifying_share`, the formatted print — not a defect); **class 3**
//! (over-taint artifact) branches on struct bookkeeping a whole-struct
//! taint marks undefined even though it is invariant for every secret
//! value (watch for this on the `?Scalar` optional's own discriminant in
//! the `combine` target, since that target taints the WHOLE array
//! including any tag byte, not just each `Scalar`'s 32 payload bytes).
//!
//! ## The three rows per (target, mode) this file is measured against
//!
//! CLAIM (`taint=yes`, built `-fvalgrind`), UNTAINTED negative control
//! (`taint=no`, same build), no-`-fvalgrind` TRAP (`taint=yes`, built
//! without the switch — `std.valgrind.doClientRequest` silently no-ops
//! without it, per `scripts/ctgrind.sh`'s header). A zero in the claim row
//! means nothing unless control and trap are also zero and the total is
//! non-zero somewhere. `std.debug.print`ing the outputs after each call is
//! the propagation witness (not constant-time by design) — its own
//! non-zero contexts are what makes an in-file zero mean "no branch
//! found" rather than "taint never arrived".
//!
//! ## What SPEC.md/README.md actually say (quoted, not paraphrased)
//!
//! Neither file makes a constant-time claim. `grep -i
//! 'constant.time\|const-time\|side.channel\|timing\|ctgrind'
//! modules/dkg/SPEC.md modules/dkg/README.md` returns NOTHING. This
//! harness is therefore evidence looking for a claim to attach to, not a
//! claim's proof — reported here as a plain absence, nothing invented and
//! nothing added to either file by this pass.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const tecdsa = @import("threshold_ecdsa");

const Scalar = root.Scalar;
const Config = root.Config;
const Dkg = root.Dkg;
const combineKeyShare = root.combineKeyShare;

// ── target "coeffs": taint every random draw entering Round 1 dealing ────

/// Wraps a real PRNG. Every `.bytes()` call is served genuine random bytes
/// from `inner` first (never fabricated), then — if `tainted` — the WHOLE
/// buffer is marked undefined via `std.valgrind.memcheck.makeMemUndefined`
/// before the caller (`protocol.randomScalar`, inside `deal()`) ever reads
/// it. The mark happens INSIDE this callback, before any consumer sees the
/// bytes, so there is no window for a from-before-tainting defined copy to
/// survive — same construction as `threshold_ecdsa`'s `TaintFirstN`,
/// simplified because `Dkg.run` has no OTHER randomness to exclude by a
/// budget (see the module doc comment above).
const TaintAll = struct {
    inner: std.Random,
    tainted: bool,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *TaintAll = @ptrCast(@alignCast(ptr));
        self.inner.bytes(buf);
        if (self.tainted) std.valgrind.memcheck.makeMemUndefined(buf);
    }

    fn random(self: *TaintAll) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

fn runCoeffs(allocator: std.mem.Allocator, tainted: bool) !void {
    var inner_prng = std.Random.DefaultPrng.init(0x646b675f636f65); // "dkg_coe"
    var wrapper: TaintAll = .{ .inner = inner_prng.random(), .tainted = tainted };
    const cfg: Config = .{ .t = 2, .n = 3 };

    const outs = Dkg.run(allocator, cfg, .{}, wrapper.random()) catch |err| {
        // Formatted regardless of taint state — still the propagation
        // witness (see the module doc comment).
        std.debug.print("aborted: {t}\n", .{err});
        return;
    };
    defer {
        for (outs) |*o| o.deinit();
        allocator.free(outs);
    }
    for (outs) |o| {
        std.debug.print("index={d} share={x} Q={x} X={x}\n", .{
            o.index,
            o.secret_share.toBytes(.big),
            o.group_public_key.toBytes(),
            o.verifying_share.toBytes(),
        });
    }
}

// ── target "combine": taint the final combined secret share directly ─────

fn realShareScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

fn runCombine(tainted: bool) !void {
    var prng = std.Random.DefaultPrng.init(0x646b675f636d62); // "dkg_cmb"
    const random = prng.random();

    const qualified = [_]bool{ true, true, true };
    var received: [3]?Scalar = .{
        realShareScalar(random),
        realShareScalar(random),
        realShareScalar(random),
    };

    // Taint each entry's 32-byte `Scalar` PAYLOAD only, right before the
    // real API call — same idiom as threshold_ecdsa's `share` target
    // tainting `ks.secret_share` directly, not a private helper
    // reimplementing the sum. ⚠ An earlier version of this target tainted
    // `std.mem.sliceAsBytes(received[0..])` (the WHOLE array in one call,
    // including `?Scalar`'s own presence discriminant) and measured 3
    // extra contexts, all at `core.zig:206`'s `r orelse
    // return error.LengthMismatch` — the exact class-3 over-taint artifact
    // this file's own doc comment warned about: whether a qualified
    // dealer's share is PRESENT is bookkeeping every real run has fixed
    // (every qualified party has a received share; that is a
    // `DriverError.LengthMismatch` precondition, never a per-run secret),
    // not a question about the SECRET value this target exists to measure.
    // Tainting only each payload, never the tag, removes that artifact
    // without narrowing what is measured about the actual secret bytes.
    if (tainted) {
        for (&received) |*r| {
            if (r.*) |*s| std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(s));
        }
    }

    const x_j = combineKeyShare(&qualified, &received) catch |err| {
        std.debug.print("combine aborted: {t}\n", .{err});
        return;
    };

    if (tecdsa.Secp256k1.basePoint.mul(x_j.toBytes(.big), .big)) |q| {
        const xg = tecdsa.Element.fromPoint(q) catch |err| {
            std.debug.print("fromPoint aborted: {t}\n", .{err});
            return;
        };
        std.debug.print("combined X={x}\n", .{xg.toBytes()});
    } else |err| {
        std.debug.print("mul aborted: {t}\n", .{err});
    }
}

// ── the harness proper ────────────────────────────────────────────────────

const Target = enum { coeffs, combine };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "coeffs")) return .coeffs;
    if (std.mem.eql(u8, s, "combine")) return .combine;
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
        .coeffs => {
            var da: std.heap.DebugAllocator(.{}) = .init;
            defer _ = da.deinit();
            try runCoeffs(da.allocator(), tainted);
        },
        .combine => try runCombine(tainted),
    }
}

// ── suggested scripts/ctgrind.sh config (for the coordinator to paste in;
// this file does not and must not edit that script itself) ───────────────
//
// declare -A TARGETS=(
//     [dkg]="coeffs combine"
// )
// declare -A MODES=(
//     [dkg]="ReleaseFast"
// )
// declare -A PATTERN=(
//     # VERIFIED against real `valgrind --tool=memcheck` logs for both
//     # targets (2026-09-09, `t=2,n=3`, ReleaseFast). ⚠ `root[.]zig` here
//     # is threshold_ecdsa's `root.zig` (`Element.fromPoint`/`.point()`),
//     # NEVER dkg's own — dkg's own `root.zig` never appeared in either
//     # target's log, but the basename collision is the same trap
//     # threshold_ecdsa's own harness documents for `root.zig`/`paillier`.
//     [dkg/coeffs]='protocol[.]zig|commit[.]zig|core[.]zig|root[.]zig|secp256k1[.]zig|common[.]zig|scalar[.]zig'
//     [dkg/combine]='core[.]zig|root[.]zig|secp256k1[.]zig'
// )
// declare -A LABEL=(
//     [dkg/coeffs]='dkg Round-1 secret coefficients + shares (a_ik/b_ik, s_ij/s_ij_prime) -> Q/x_j'
//     [dkg/combine]='dkg final combined secret share (x_j = combineKeyShare) -> basePoint.mul'
// )
//
// Measured (ReleaseFast, this pass, 2026-09-09): coeffs total=98 (control=0,
// trap=0); combine total=5 (control=0, trap=0) AFTER fixing an over-taint
// artifact this same pass found and removed (an earlier, whole-array-taint
// version of `combine` measured 8, 3 of which were `core.zig:206`'s `?Scalar`
// presence-discriminant, not the secret payload — see `runCombine`'s doc
// comment). ⚠ One of `combine`'s 5 contexts (the mul at `x_j.toBytes()`,
// fully inlined into `runCombine` itself at ReleaseFast) attributes to
// `ctgrind_harness.zig`, not to `secp256k1.zig` — the exact same disputed
// rejectIdentity call as the OTHER context that DOES show `secp256k1.zig`,
// just relocated by the inliner. Neither PATTERN above matches
// `ctgrind_harness[.]zig` (adding it would be the k256-incident fail-open
// this repo's classifier exists to refuse), so that ONE context lands in
// `unattr` under `scripts/ctgrind.sh --check` and needs a human-documented
// exception, not a pattern change — see this pass's harness report for the
// full per-context file:line/class breakdown (a source comment is the
// wrong place for a table the code will make stale).
