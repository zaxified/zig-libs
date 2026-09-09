// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Partially
//! constant-time — read the boundary, do not round it up" section, as an
//! actual committed program instead of a claim nobody re-runs. Run it through
//! `zig build ctgrind -Dctgrind-module=bfv -Dctgrind-valgrind=…` plus
//! `valgrind --tool=memcheck` by hand — `scripts/ctgrind.sh` has no
//! per-module TARGETS/MODES/PATTERN/LABEL entry for `bfv` yet; the suggested
//! lines are at the bottom of this comment for the coordinator to paste in.
//!
//! NOT wired into `zig build test-bfv`: memcheck's context count is
//! valgrind's own output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## Quoting the claim this measures
//!
//! `SPEC.md`, "Threats / caveats (Part 1)": *"What IS source-level constant
//! time now: the ternary sampler (`sampleTernary` draws with the fixed-cost
//! `uintLessThanBiased` instead of a rejection loop and selects the trit with
//! an arithmetic mask, so neither the draw nor the store branches on the
//! secret), and the word-arithmetic leaves every secret-bearing product
//! routes through (`addMod`/`subMod`/`Modulus.mul`/`Shoup.mul` end in a
//! masked conditional subtract, `modarith.csub`, and the `%q` division that
//! had data-dependent latency on some µarch is gone). What is NOT, and is not
//! claimed to be: `powMod`/`invMod`/`primitive2NthRoot`/the auxiliary-prime
//! search are public-data setup and remain variable-time;
//! `sampleUniform` still uses the rejection-based `uintLessThan` (its output
//! is a public mask, not a secret); `decrypt`/`noiseBudget`/`centerRaw`/
//! `auxResidues` branch on reconstructed coefficient values;
//! `relinearize`'s digit decomposition is value-shaped... Above all this is
//! **source-level** CT — the compiler may rematerialise a branch from a
//! mask, and nothing here is verified codegen or a microarchitectural
//! claim."*
//!
//! That paragraph is the claim; this harness is the first time it is run
//! under an instrument rather than read.
//!
//! ## What is tainted, per target — the RLWE secret through the REAL API
//!
//! Three targets, one taint each, all reached through `bfv.Bfv(P)`'s public
//! entry points (never a private `…Inner`, which the module's own
//! `builtin.is_test` guard makes unreachable from this non-test executable
//! anyway — see `bfv.zig`'s "Test-only guards" doc comment):
//!
//!   - **`keygen`** — `keyGen` does not TAKE a secret key, it PRODUCES one, so
//!     what this harness taints is the ENTROPY `keyGen` draws through
//!     `io.randomSecure` — the bytes that `sampleTernary` turns into `s`, `a`
//!     `keyGen` also draws (`sampleUniform`), and `e`. `SyntheticIo` below is
//!     a `std.Io` whose `randomSecure` slot hands back deterministic bytes
//!     and (when asked) marks them `MAKE_MEM_UNDEFINED` before returning —
//!     the same "observe three vtable slots, delegate the rest" shape
//!     `modules/entropy/src/root.zig`'s own `CountingIo` test double uses,
//!     with `randomSecure` REPLACED instead of merely counted. This measures
//!     `sampleTernary`+`sampleUniform` (the draw and the mask-select) AND the
//!     ring arithmetic downstream of them (`a.mul(&s,…)`, `addAssign`,
//!     `negate`) in one call, through the actual `keyGen(io)` production path.
//!   - **`decrypt`** — `decrypt(sk: *const SecretKey, ct: *const Ciphertext)`
//!     takes the secret key as a plain argument, so this harness builds a
//!     REAL keypair and a REAL ciphertext first (both off UNTAINTED
//!     `SyntheticIo` entropy, so `encrypt`'s own retry-free happy path runs
//!     exactly as it would in production), and only THEN marks `sk`'s bytes
//!     undefined and reloads them through a volatile pointer before calling
//!     `decrypt`. Exercises `Ring.mul` (c1·s), the CRT `reconstruct` and the
//!     round-half-up rescale — the one place `SPEC.md` names a
//!     reduction-shaped branch this harness can actually reach (see "the
//!     `reconstruct` candidate" below).
//!   - **`encrypt`** — `encrypt(pk, pt: *const Plaintext, io)` takes the
//!     plaintext directly, so this harness constructs a `Plaintext`, taints
//!     its `coeffs`, reloads it volatile, and calls `encrypt` with a REAL
//!     (untainted) public key and UNTAINTED entropy for `u,e0,e1` — isolating
//!     "does a branch depend on the message" from "does a branch depend on
//!     the encryption randomness", the latter not being this claim's subject
//!     (the errors are ephemeral per-ciphertext values, not the caller's
//!     "secret" in the sense `SPEC.md`'s CT section is about, and are drawn
//!     fresh from the CSPRNG on every call regardless).
//!
//! ## The `reconstruct` candidate — read before trusting an `in-file 0`
//!
//! `Bfv.reconstruct` (`bfv.zig`, CRT lift used by `decrypt` on the
//! secret-dependent phase) ends `if (acc >= q_product) acc -= q_product;` —
//! an `if`, not `modarith.csub`'s arithmetic mask. This is exactly the
//! "modular reduction over a machine word" shape the campaign has flagged
//! repeatedly: it is a genuine class-1 finding if it disassembles to a real
//! conditional jump, and a non-finding if LLVM turns it into a `cmov`/`sbb`
//! at `-Doptimize=ReleaseFast`.
//!
//! MEASURED 2026-09-09 (zig 0.16.0, x86_64, this exact harness): inlined into
//! `decrypt`'s call site, `reconstruct`'s `Modulus.reduce`/`csub` compiles to
//! `cmp`+`cmova`/`cmovae`+`sbb` — a `cmov`, not a jump — and correspondingly
//! this exact line did NOT appear as a flagged context with `sk` tainted.
//! Read that as "not disproven", not "proven safe": the WITNESS bucket DID
//! fire (the final `decoded` print carries flagged contexts), so the taint
//! demonstrably reaches the printed output through this function, yet the
//! `cmov` itself registered no error — memcheck's V-bit propagation through
//! the wide `mulx`/`adc` Barrett chain is not something this harness
//! independently re-verified bit-for-bit. Take the "0" here as "no branch
//! found by this run", the same caveat every other clean row in this
//! collection carries.
//!
//! What decrypt DOES demonstrably branch on: the final round-half-up rescale
//! `(2·t·v+q)/(2·q)` is a `u128/u128` division (`QRescale` is 128 bits for
//! `test_mul`), which LLVM does NOT fold into a magic-number multiply at this
//! width — it calls `compiler_rt.udivmod` (`lib/std/…/udivmod.zig:187,202`),
//! a general long-division routine that branches on the dividend by
//! construction. `v`, the dividend, is exactly the secret-dependent
//! reconstructed phase. This is `SPEC.md`'s own sentence ("decrypt … branch
//! on reconstructed coefficient values") pinned to two exact lines instead of
//! left as an unmeasured admission.
//!
//! `encryptInner`'s `scaledPlaintext` (the very first thing `encrypt` does to
//! the tainted plaintext, `bfv.zig:686`) is the other measured branch, and
//! the more interesting one: its `Modulus.reduce`/`Shoup.mul` calls compile
//! to a real `cmp`+`jb` — a genuine conditional JUMP, not a `cmov` — at all
//! four inlined call sites. This is the SAME `modarith.csub` this binary
//! compiles to a `cmov` roughly 98 other times (grepped across the whole
//! disassembly) — i.e. a single leaf function, one call site gets branch
//! codegen and every other measured call site gets the masked form. This is
//! this module's own instance of the exact phenomenon the campaign has
//! measured before on `bls12_381`/`signal`: codegen is a property of the call
//! site, not of the function.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default
//!    outside Debug. Built WITHOUT `-fvalgrind`, `--taint=yes` silently
//!    behaves like `--taint=no` — measured as its own row, not assumed.
//! 2. An optimizer is in principle free to keep a defined copy of a tainted
//!    value in a register. `reloadVolatile` forces one real load from
//!    freshly-tainted memory immediately before the call under test, for the
//!    two targets (`decrypt`, `encrypt`) that taint a value BEFORE calling
//!    into the module. `keygen` has no such reload because the taint there
//!    happens inside `SyntheticIo.onRandomSecure`, at the exact point the
//!    module reads the entropy — there is no pre-call copy to go stale.
//! 3. ReleaseFast only, same reasoning as every other harness in this
//!    collection: `Debug`/`ReleaseSafe` add overflow checks that branch on
//!    tainted arithmetic and bury the signal, and Debug's self-hosted
//!    backend is not readable by valgrind's DWARF parser at all
//!    (`scripts/ctgrind.sh` § MODES).
//!
//! ## Parameters: `params.test_mul`, not the security-grade set
//!
//! `params.test_mul` (`N=16`, two ~17/20-bit primes) is used for all three
//! targets. It is a correctness-only toy set (`SPEC.md` "Security status"),
//! chosen here purely so a memcheck run over `keyGen`/`encrypt`/`decrypt`
//! finishes in seconds rather than minutes — the constant-time PROPERTY this
//! harness checks is a property of the arithmetic shape (masked select,
//! masked conditional-subtract vs a real `if`), which does not change with
//! `N` or the prime widths. `sec_n8192_logq218` would exercise the identical
//! code paths at ~500x the coefficient count for no additional evidence.
//!
//! ## The propagation witness
//!
//! Each target formats its result (`keygen`: the public key; `decrypt`: the
//! recovered plaintext; `encrypt`: the ciphertext) through `std.debug.print`,
//! which is not constant-time by design. A non-zero WITNESS count next to a
//! small, itemised in-file count is what makes the itemisation mean "no
//! branch found", not "the harness never ran".
//!
//! ## Measured 2026-09-09 (zig 0.16.0 / x86_64 / ReleaseFast / this harness)
//!
//! Claim rows (tainted), errors/contexts from `valgrind --tool=memcheck
//! --error-exitcode=99 --num-callers=20`; every UNTAINTED control and every
//! no-`-fvalgrind` trap row was 0/0 for all three targets (6 runs, all
//! confirmed clean — see report):
//!
//!   - `keygen`: 478 errors / 29 contexts. In-file (bfv.zig): `sampleTernary`
//!     is_neg select, bfv.zig:655, TWO call sites (`s` at keyGenInner:711,
//!     `e` at keyGenInner:713) — **class 1, confirmed by disassembly**: both
//!     compile to `test %rcx,%rcx` + `je`/`jne`, a real conditional jump on
//!     the drawn trit, contradicting the "arithmetic mask" doc comment on
//!     this exact function. Also flagged: `sampleUniform`'s rejection-based
//!     `uintLessThan` (std `Random.zig:170`, bfv.zig:670) — this is the
//!     documented-variable-time draw for the PUBLIC `a`, and it is flagged
//!     here ONLY because `SyntheticIo` taints the whole keyGen entropy
//!     stream and cannot isolate `s`/`e`'s draws from `a`'s — an over-taint
//!     artifact of this harness's granularity, not a new finding (SPEC.md
//!     already states `a` is public and this path is variable-time).
//!   - `encrypt`: 272 errors / 17 contexts. In-file: `modarith.csub` inside
//!     `scaledPlaintext` (bfv.zig:686 / modarith.zig:58), FOUR call sites —
//!     **class 1, confirmed by disassembly**: `cmp`+`jb`, not a `cmov`. See
//!     "The `reconstruct` candidate" above for why this is notable (same
//!     function, safe everywhere else measured in this binary).
//!   - `decrypt`: 71 errors / 6 contexts. In-file: none registered (see
//!     above — `reconstruct`'s own `csub` compiled to `cmov` here and did not
//!     fire). The two non-witness contexts are `compiler_rt.udivmod`
//!     (`udivmod.zig:187,202`), reached from decrypt's `u128` rescale
//!     division — SPEC.md's own documented "branch on reconstructed
//!     coefficient values", now pinned to two lines.
//!
//! Every target's WITNESS bucket (std's `Writer.zig`/`fmt.zig` digit
//! formatting, `linux.zig`'s `errno` off the `writev` syscall) fired
//! non-zero, confirming the taint reached the printed value in all three
//! runs.
//!
//! ## Suggested config lines for scripts/ctgrind.sh (coordinator to paste in)
//!
//! ```
//! TARGETS[bfv]="keygen encrypt decrypt"
//! MODES[bfv]="ReleaseFast"
//! # Random.zig: sampleUniform's rejection-based draw for the PUBLIC `a` --
//! # named rather than left `unattr` because this harness's whole-stream
//! # entropy taint cannot separate it from s/e's draws (see "Measured" above).
//! PATTERN[bfv/keygen]='bfv[.]zig|modarith[.]zig|ntt[.]zig|ring[.]zig|Random[.]zig'
//! PATTERN[bfv/encrypt]='bfv[.]zig|modarith[.]zig|ntt[.]zig|ring[.]zig'
//! # udivmod.zig: the u128 rescale division compiler_rt supplies -- SPEC.md's
//! # own "decrypt branches on reconstructed coefficient values", now measured.
//! PATTERN[bfv/decrypt]='bfv[.]zig|modarith[.]zig|ntt[.]zig|ring[.]zig|udivmod[.]zig'
//! LABEL[bfv/keygen]='bfv keyGen: ternary/uniform samplers + ring arithmetic'
//! LABEL[bfv/encrypt]='bfv encrypt: tainted plaintext through scaledPlaintext+ring mul'
//! LABEL[bfv/decrypt]='bfv decrypt: tainted secret through ring mul + CRT reconstruct'
//! ```

const std = @import("std");
const builtin = @import("builtin");
const bfv = @import("root.zig");

/// A `std.Io` that hands `randomSecure` deterministic, optionally-tainted
/// bytes instead of a real `getrandom(2)` draw, and delegates everything else
/// (here: `swapCancelProtection`, which `entropy.fill` also calls) to a real
/// inner `std.Io`.
///
/// Same construction as `modules/entropy/src/root.zig`'s own `CountingIo`
/// test double: copy the inner vtable, override exactly the slots reached
/// from `entropy.fill` (`randomSecure`, `swapCancelProtection`), and bind
/// `userdata` to this struct. Every OTHER vtable slot would be mis-bound
/// (`CountingIo`'s doc comment explains why) — fine here because `bfv.keyGen`
/// / `bfv.encrypt` reach `io` through `entropy.SecureSource` alone, which
/// calls only those two functions.
const SyntheticIo = struct {
    inner: std.Io,
    /// When true, every buffer `onRandomSecure` hands back is marked
    /// `MAKE_MEM_UNDEFINED` before the caller reads it — this is where the
    /// "entropy entering keyGen" taint actually happens, at the exact point
    /// the module receives it, so there is nothing for an optimizer to have
    /// cached from before the taint (see trap 2 in the module doc above).
    taint: bool,
    vtable: std.Io.VTable = undefined,
    /// Domain-separates successive draws so `s`, `a`, `e` (keygen) or
    /// `u`, `e0`, `e1` (encrypt) are not all identical bytes.
    counter: u64 = 0,

    fn io(self: *SyntheticIo) std.Io {
        self.vtable = self.inner.vtable.*;
        self.vtable.randomSecure = onRandomSecure;
        self.vtable.swapCancelProtection = onSwapCancelProtection;
        return .{ .userdata = self, .vtable = &self.vtable };
    }

    fn onRandomSecure(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
        const self: *SyntheticIo = @ptrCast(@alignCast(userdata.?));
        self.counter += 1;
        var st = std.crypto.hash.sha3.Shake256.init(.{});
        st.update("ctgrind-bfv-harness-entropy-v1");
        st.update(std.mem.asBytes(&self.counter));
        st.squeeze(buffer);
        if (self.taint) std.valgrind.memcheck.makeMemUndefined(buffer);
        return;
    }

    fn onSwapCancelProtection(userdata: ?*anyopaque, new: std.Io.CancelProtection) std.Io.CancelProtection {
        const self: *SyntheticIo = @ptrCast(@alignCast(userdata.?));
        return self.inner.swapCancelProtection(new);
    }
};

/// Mark `value`'s whole byte representation undefined, iff `tainted`.
fn taintBytes(comptime T: type, tainted: bool, value: *T) void {
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(value));
}

/// Force one real, byte-at-a-time volatile reload of `value`, so the call
/// under test cannot be fed a register-cached copy that predates
/// `taintBytes` — see trap 2 in the module doc comment above.
fn reloadVolatile(comptime T: type, value: *const T) T {
    var out: T = undefined;
    const src = std.mem.asBytes(value);
    const dst = std.mem.asBytes(&out);
    for (dst, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { keygen, encrypt, decrypt };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "keygen")) return .keygen;
    if (std.mem.eql(u8, s, "encrypt")) return .encrypt;
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

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, @tagName(target) });

    // A real `std.Io` backend so `SyntheticIo.onSwapCancelProtection` has
    // something genuine to delegate to. Its OWN entropy is never read: every
    // `randomSecure` draw in this harness goes through `SyntheticIo`'s
    // override instead.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const base_io = threaded.io();

    const P = bfv.params.test_mul;
    const BfvT = bfv.Bfv(P);
    const instance = try BfvT.init();

    switch (target) {
        .keygen => {
            // The one target where the taint is applied INSIDE the entropy
            // source, not to a pre-built value — see "What is tainted" above.
            var entropy_src: SyntheticIo = .{ .inner = base_io, .taint = tainted };
            const kp = instance.keyGen(entropy_src.io());
            // Propagation witness: the public key is a function of the
            // (possibly tainted) s/a/e draws (`p0 = -(a*s+e)`, `p1 = a`).
            std.debug.print("pk.p0={any} pk.p1={any}\n", .{ kp.pk.p0.limbs, kp.pk.p1.limbs });
        },

        .encrypt => {
            // Real, UNTAINTED keypair -- the public key `encrypt` reads is
            // not this claim's subject (see module doc: only `pt` is
            // tainted here).
            var clean_src: SyntheticIo = .{ .inner = base_io, .taint = false };
            const kp = instance.keyGen(clean_src.io());

            var pt = BfvT.Plaintext.zero(P.t);
            for (&pt.coeffs, 0..) |*c, j| c.* = (@as(u64, j) * 7 + 3) % P.t;
            taintBytes(BfvT.Plaintext, tainted, &pt);
            const pt_loaded = reloadVolatile(BfvT.Plaintext, &pt);

            // UNTAINTED encryption randomness -- see module doc for why the
            // per-ciphertext u/e0/e1 draw is deliberately out of scope here.
            var enc_src: SyntheticIo = .{ .inner = base_io, .taint = false };
            const ct = instance.encrypt(&kp.pk, &pt_loaded, enc_src.io());
            // Propagation witness: c0 = Delta*m + p0*u + e0 carries the
            // (possibly tainted) plaintext.
            std.debug.print("ct0={any} ct1={any}\n", .{ ct.components[0].limbs, ct.components[1].limbs });
        },

        .decrypt => {
            // Build a REAL keypair and a REAL, valid ciphertext first, both
            // off UNTAINTED entropy, so `decrypt` sees exactly the input
            // shape it would in production -- only `sk` is tainted, and only
            // just before the call under test.
            var clean_src: SyntheticIo = .{ .inner = base_io, .taint = false };
            var kp = instance.keyGen(clean_src.io());

            var pt = BfvT.Plaintext.zero(P.t);
            for (&pt.coeffs, 0..) |*c, j| c.* = @as(u64, j) % P.t;

            var enc_src: SyntheticIo = .{ .inner = base_io, .taint = false };
            const ct = instance.encrypt(&kp.pk, &pt, enc_src.io());

            taintBytes(BfvT.SecretKey, tainted, &kp.sk);
            const sk_loaded = reloadVolatile(BfvT.SecretKey, &kp.sk);

            const decoded = instance.decrypt(&sk_loaded, &ct);
            // Propagation witness: the recovered plaintext is exactly
            // Dec(Enc(pt)), so a tainted `sk` byte that reached `decrypt`'s
            // arithmetic shows up here.
            std.debug.print("decoded={any}\n", .{decoded.coeffs});
        },
    }
}
