// SPDX-License-Identifier: MIT

//! ctgrind_harness — the measured evidence for `SPEC.md`'s "Source-level
//! constant-time in the key path; not verified codegen" paragraph, quoted in
//! full below rather than paraphrased. That paragraph makes specific claims
//! (`sampleBit`/`sampleError` are fixed-cost, `lweKeyGen`/`glweKeyGen` are
//! fixed-trip loops over `sampleBit`, `gadget.decompose` branches only on
//! ciphertext coefficients and never on key material) and says plainly that
//! no timing measurement backed any of it. This file is that measurement.
//! Run through `../../../scripts/ctgrind.sh tfhe` once the coordinator wires
//! the `TARGETS`/`MODES`/`PATTERN`/`LABEL` entries suggested at the bottom of
//! this comment — until then, drive it directly:
//!
//!     zig build ctgrind -Dctgrind-module=tfhe -Dctgrind-valgrind=true -Doptimize=ReleaseFast
//!     valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!         --max-stackframe=16777216 \
//!         zig-out/ctgrind/ctgrind-tfhe <target> <taint>
//!
//! The `--max-stackframe` flag is NOT optional — see trap 3 below; without
//! it every row is flooded with false "Invalid read/write" noise from
//! `std.Io.Threaded`'s stack footprint, unrelated to any taint.
//!
//! NOT wired into `zig build test-tfhe` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on.
//! `zig build check-ctgrind` compiles this (rot guard only, no valgrind).
//!
//! ## The quoted claim (`SPEC.md`, "Source-level constant-time…")
//!
//! > The secret samplers are fixed-cost and branch-free: `sampleBit` takes
//! > the top bit of one `u32` draw … `lweKeyGen`/`glweKeyGen` are fixed-trip
//! > loops over `sampleBit`. What this does not claim: the compiler may
//! > still reintroduce a branch — this is source-level constant time, not
//! > verified machine code, and no timing measurement was taken.
//! > `gadget.decompose` still branches on digit values, but it is only ever
//! > applied to ciphertext mask/body coefficients, never to key material.
//!
//! ## Why every target goes through `io`-taking production entry points
//!
//! `lweKeyGenForTest`/`glweKeyGenForTest`/`lweEncryptForTest`/
//! `bootstrapKeyGenForTest`/`keySwitchKeyGenForTest` all open with
//! `comptime if (!builtin.is_test) @compileError(…)` (`tfhe.zig`, "Test-only
//! guards and where they may sit") — a deliberate defence against a
//! seeded-PRNG key path leaking into production, and it makes every one of
//! them **unreachable from this file**: `ctgrind_harness.zig` is built by
//! `zig build ctgrind` as a plain executable (`b.addExecutable`, not
//! `addTest`), so `builtin.is_test` is `false` here regardless of what the
//! binary is used for afterwards. There is no way around this without
//! editing `tfhe.zig` (out of scope for this pass) — nor should there be:
//! the guard is exactly why a ctgrind harness has to prove its taint through
//! the real `io: std.Io` entry points (`lweKeyGen`, `glweKeyGen`,
//! `lweEncrypt`, `glweEncrypt`, `bootstrapKeyGen`, `keySwitchKeyGen`)
//! instead of a shortcut. `SyntheticIo` below is what makes that possible —
//! the same "observe/override a couple of vtable slots, delegate the rest"
//! shape `modules/bfv/src/ctgrind_harness.zig`'s own `SyntheticIo` and
//! `modules/entropy/src/root.zig`'s test-only `CountingIo` already use in
//! this collection, applied here rather than reinvented.
//!
//! ## The four targets
//!
//!   * `keygen`   — taints the ENTROPY `lweKeyGen`/`glweKeyGen` draw through
//!     `io.randomSecure` (`SyntheticIo.taint = true`), exercising the real
//!     `sampleBit` draw→bit derivation (`random.int(u32) >> 31`) end to end.
//!   * `encrypt`  — REAL (untainted) key and REAL (untainted) encryption
//!     entropy; only the plaintext (`mu` for `lweEncrypt`, `msg` for
//!     `glweEncrypt`) is tainted, isolating "does a branch depend on the
//!     message" from "does a branch depend on the mask/noise draw" (the
//!     latter is ephemeral per-ciphertext randomness, not the SPEC's
//!     "secret" — same separation `bfv`'s harness makes for the same reason).
//!   * `decrypt`  — REAL key and REAL ciphertext (both off untainted entropy)
//!     built through the production API; only the LWE/GLWE secret key is
//!     tainted, just before `lweDecryptBit`/`lwePhase`/`glwePhase` (pure
//!     functions, no `io` — nothing to route through `SyntheticIo` here).
//!   * `bootstrap` — the task's "most interesting path". Taints BOTH the LWE
//!     key (`lwe_key.s`) and the GLWE key (`glwe_key.s`) as they enter
//!     `bootstrapKeyGen`/`keySwitchKeyGen` (with REAL, untainted entropy for
//!     those functions' own row-masking draws — isolating "does the KEY
//!     VALUE reach a branch" from "does the encryption randomness"), then
//!     drives the REAL `bootstrap`: mod-switch → `blindRotate`'s `n`
//!     CMux/`externalProduct` steps over the now-tainted bootstrap key →
//!     sample-extract → key-switch through the now-tainted key-switch key.
//!     The ciphertext being bootstrapped is built from an UNTAINTED copy of
//!     the SAME key, so `a_tilde`/`b_tilde` (blindRotate's rotation
//!     exponents) stay public data throughout — see below for why that
//!     separation is exactly what the module's own design makes true.
//!
//! ## Is there a secret-indexed memory access in blind rotation? Measured,
//! ## not read off the source — the source shape and the compiled shape
//! ## disagree in BOTH directions here.
//!
//! `blindRotate` (`tfhe.zig`) computes
//! `rot = glweMulMonomial(&acc, a_tilde[i] % two_n)` — the rotation EXPONENT
//! is `a_tilde[i]`, the mod-switched coefficient of the INPUT ciphertext's
//! mask, i.e. public evaluator-visible data. The secret bit `s_i` is never
//! used as an array index or a rotation amount anywhere in this file — this
//! part of the source claim holds, AND it measures clean: across every
//! `bootstrap` run in this harness, `poly.zig`'s `mulMonomial` (the only
//! function that ever indexes an array by a rotation amount) never appears
//! in a single tainted context, confirmed for a rotation amount (`a_tilde`)
//! that is always public in this harness's construction. The secret bit
//! `s_i` itself appears in exactly two places: (a) inside `bootstrapKeyGen`,
//! added as a gadget term into an already uniformly-masked GLWE(0) row
//! (`ggswEncryptPolyInner`'s `ra.a.addAssign(&scaled)`) — producing an
//! ENCRYPTION of `s_i`, never `s_i` itself, in memory the evaluator will
//! read; and (b) as the `C` operand of `cmux(&bsk.ggsw[i], &acc, &rot)`,
//! resolved by `externalProduct` — a fixed sequence of polynomial
//! multiplies/adds over two ENCRYPTED operands, run unconditionally for
//! every `i`. There is no secret-INDEXED table lookup here by construction.
//!
//! Two places downstream DO branch on tainted data once the taint is
//! followed all the way through, and in each case the finding is the
//! OPPOSITE of what the source's own framing suggests — see the "disassemble
//! before you classify" lesson from `bls12_381`/`signal`/`std.mem.allEqual`:
//!
//!   1. **A genuine class-1 branch where the source claims branch-free.**
//!      `Poly.mul` at the `toy` params' `N=256` dispatches to
//!      `ntt.Engine(256).mulTorus` (`poly.zig`'s `ntt_min_degree = 256`).
//!      `ntt.zig`'s header says every op in it "is written with an explicit
//!      arithmetic `mask()`/`@intFromBool` select … for speed, not secrecy
//!      (nothing in this file touches a secret)". That premise is false once
//!      `Poly.mul` runs on secret key material, which `tfhe.zig` does
//!      routinely (`glwePhase`'s `ct.a.mul(&key.s)`, `glweEncryptInner`'s
//!      `a.mul(&key.s)` inside every GGSW row's masking). MEASURED (this
//!      pass, `zig build ... -Doptimize=ReleaseFast`, disassembled with
//!      `objdump -d`): `addMod`'s (`ntt.zig:93`) and `reduce128`'s
//!      (`ntt.zig:127`, inlined into `mulMod`, `ntt.zig:133`) masked
//!      `r -%= p & mask(@intFromBool(r >= p))` compiles to a REAL `jb`
//!      (conditional jump) at 8 of its inlined call sites — both inside
//!      `ntt.Engine(256).forward`'s butterfly (the two calls that process
//!      the SECRET operand's low/high 16-bit split; the two calls processing
//!      the PUBLIC ciphertext operand show no taint) and inside
//!      `mulTorus`'s cross-term combination — while the IDENTICAL source
//!      pattern compiles to a `cmovb`/`cmovae` (genuinely branch-free) at
//!      other call sites inside `ntt.Engine(256).inverse`, inlined a few
//!      hundred bytes further down the same function. Same masked-select
//!      idiom, same file, same compiler flags, two different machine-code
//!      shapes depending on the surrounding loop structure — LLVM's choice,
//!      not something `-fvalgrind`/`ReleaseFast` alone predicts. This is a
//!      genuine "Conditional jump…depends on uninitialised value(s)" context
//!      — an address COMPARISON feeding a real jump, not a memory-address
//!      computation — on data that traces back to the GLWE/LWE secret key,
//!      not merely to a value the output discloses anyway: **class 1**.
//!   2. **No branch where the source (and `SPEC.md`) warns of one.**
//!      `gadget.decompose`'s `if (d >= half) { … } else { … }`
//!      (`gadget.zig:58`) is a plain source-level `if`, and `SPEC.md`
//!      explicitly flags it: "`gadget.decompose` still branches on digit
//!      values". MEASURED: it never appears as a tainted context in any
//!      `bootstrap` run, even though `blindRotate`'s accumulator `acc` IS
//!      demonstrably undefined from the first `cmux` onward (confirmed with
//!      a hand-rolled reproduction using `std.valgrind.memcheck.checkMemIsDefined`
//!      after each step, built and thrown away for this pass, not shipped)
//!      — meaning `decomposeGlwe` genuinely runs on tainted bytes and still
//!      produces zero. LLVM appears to auto-if-convert this particular
//!      diamond into a branch-free select despite the plain `if` in source.
//!      Not a finding against the module — the opposite of one — but
//!      reported as measured rather than assumed, symmetrically with (1).
//!
//! `mulSchoolbook`'s fallback `if (k < N)` branches only on the LOOP INDEX
//! `k = i+j`, never on a coefficient value (and is not even the path `toy`
//! params take, since `N=256 >= ntt_min_degree`), so it is excluded by
//! construction rather than by measurement.
//!
//! ## The three traps (see `ct25519`'s harness for the fuller writeup of the
//! ## first two)
//!
//! 1. `std.valgrind.doClientRequest` no-ops without `-fvalgrind`, off by
//!    default outside Debug — the `-fvalgrind=false` row is the trap that
//!    catches a silently-clean run.
//! 2. An optimizer could in principle keep an already-defined copy of a
//!    value from before it was marked undefined. For `encrypt`/`decrypt`/
//!    `bootstrap`, which taint a value BEFORE calling into the module,
//!    `reloadVolatile` forces one real volatile load of every tainted byte
//!    immediately before the call under test. `keygen` needs no such reload:
//!    the taint happens INSIDE `SyntheticIo.onRandomSecure`, at the exact
//!    point the module receives the bytes, so there is no earlier copy to
//!    go stale (same reasoning as `bfv`'s harness).
//! 3. **Specific to this harness's use of `std.Io.Threaded`**: run under
//!    plain `valgrind --tool=memcheck --error-exitcode=99 --num-callers=20`
//!    (no other flags), EVERY target — even `keygen` doing nothing but two
//!    key draws — reports thousands of bogus "Invalid read"/"Invalid write"
//!    errors and a `Warning: client switching stacks?  SP change: … to
//!    suppress, use: --max-stackframe=2707656 or greater`. That warning names
//!    its own fix: this binary's `main` frame (the `std.Io.Threaded` value
//!    plus, for `bootstrap`, the `BootstrapKey`/`KeySwitchKey` locals) is
//!    larger than memcheck's default 2 MB stack-frame heuristic, so a single
//!    legitimate large stack allocation gets misread as a stack switch, and
//!    everything "beyond" it as out-of-bounds. Pass
//!    **`--max-stackframe=16777216`** (or larger) and the false flood is
//!    gone — confirmed by re-running every target/taint/mode combination
//!    with and without the flag and diffing the surviving contexts. This is
//!    a valgrind-configuration fix, not a taint-classification one: it does
//!    not touch, hide, or reclassify a single real context, and every number
//!    in this pass's report was taken with the flag on.
//!
//! ## Parameters
//!
//! `root.params.toy` (`n=64`, `N=256`) throughout — the only parameter set
//! this module ships, and small enough that `blindRotate`'s 64 CMux steps
//! finish under memcheck in well under a minute.
//!
//! ## The propagation witness
//!
//! Every target formats its result through `std.debug.print`, not constant
//! time by design. A non-zero WITNESS count next to a small, itemised
//! in-file count is what makes the itemisation mean "no branch found", not
//! "the harness never ran" — see `scripts/ctgrind.sh`'s "the SECOND trap".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Toy = root.Tfhe(root.params.toy);
const T = root.Torus;

/// A `std.Io` that hands `randomSecure` deterministic, optionally-tainted
/// bytes instead of a real `getrandom(2)` draw, delegating everything else
/// (here: `swapCancelProtection`, which `entropy.fill` also calls) to a real
/// inner `std.Io`. Same construction as `modules/bfv/src/ctgrind_harness.zig`'s
/// `SyntheticIo` / `modules/entropy/src/root.zig`'s test-only `CountingIo`:
/// copy the inner vtable, override exactly the slots `entropy.SecureSource`
/// reaches, bind `userdata` to this struct. Every OTHER vtable slot would be
/// mis-bound — fine here because every production entry point in `tfhe.zig`
/// reaches `io` through `entropy.SecureSource` alone, which calls only these
/// two functions.
const SyntheticIo = struct {
    inner: std.Io,
    /// When true, every buffer `onRandomSecure` hands back is marked
    /// `MAKE_MEM_UNDEFINED` before the caller reads it — the taint happens
    /// at the exact point the module receives the entropy, so there is
    /// nothing for an optimizer to have cached from before it (trap 2).
    taint: bool,
    vtable: std.Io.VTable = undefined,
    /// Domain-separates successive draws so e.g. `s` (LWE key) and `s`
    /// (GLWE key), or a GGSW row's mask and its noise, are not identical
    /// bytes.
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
        st.update("ctgrind-tfhe-harness-entropy-v1");
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
fn taintBytes(comptime V: type, tainted: bool, value: *V) void {
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(value));
}

/// Force one real, byte-at-a-time volatile reload of `value`, so the call
/// under test cannot be fed a register-cached copy that predates
/// `taintBytes` — see trap 2 above.
fn reloadVolatile(comptime V: type, value: *const V) V {
    var out: V = undefined;
    const src = std.mem.asBytes(value);
    const dst = std.mem.asBytes(&out);
    for (dst, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { keygen, encrypt, decrypt, bootstrap };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "keygen")) return .keygen;
    if (std.mem.eql(u8, s, "encrypt")) return .encrypt;
    if (std.mem.eql(u8, s, "decrypt")) return .decrypt;
    if (std.mem.eql(u8, s, "bootstrap")) return .bootstrap;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn identityLut() Toy.Poly {
    return Toy.testPolynomial(2, .{ Toy.encodeBit(0), Toy.encodeBit(1) });
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, @tagName(target) });

    // A real `std.Io` backend so `SyntheticIo.onSwapCancelProtection` has
    // something genuine to delegate to. Its OWN entropy is never read:
    // every `randomSecure` draw in this harness goes through a
    // `SyntheticIo` override instead, real or tainted as each site chooses.
    //
    // Deliberately NOT deinitialised: `Threaded.deinit`'s `sigaction`
    // restore reads past what memcheck considers the live stack region
    // (measured: ~7000 "Invalid read" errors across ~280 contexts, all
    // rooted at `Threaded.zig:1715`/`:1716`/`:1719`, identical whether
    // `tainted` is true or false) -- a teardown artifact of this Io
    // backend under valgrind, unrelated to anything this harness measures.
    // This is a one-shot diagnostic binary the process exit reclaims
    // completely; leaving the pool running to process exit is deliberate,
    // not an oversight, and sidesteps the noise instead of masking it.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{}); // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    const base_io = threaded.io();

    switch (target) {
        // The one target where the taint is applied INSIDE the entropy
        // source, not to a pre-built value — see module doc "the two traps".
        .keygen => {
            var src: SyntheticIo = .{ .inner = base_io, .taint = tainted };
            const lwe_key = Toy.lweKeyGen(64, src.io());
            const glwe_key = Toy.glweKeyGen(src.io());
            // Propagation proof: a checksum of the derived key material,
            // formatted through a non-constant-time path.
            var chk: T = 0;
            for (lwe_key.s) |x| chk ^= x;
            for (glwe_key.s.c) |x| chk ^= x;
            // Through `toBytes`: `T` is a u32, and `{x}` on an integer drops leading
            // zeros, so a small checksum would print fewer hex digits than the
            // output pin's floor and the pin would track the VALUE, not the code.
            std.debug.print("keygen ctgrind_result={x}\n", .{std.mem.toBytes(chk)});
        },

        // REAL (untainted) key and REAL (untainted) mask/noise entropy;
        // only the plaintext is tainted.
        .encrypt => {
            var clean1: SyntheticIo = .{ .inner = base_io, .taint = false };
            var clean2: SyntheticIo = .{ .inner = base_io, .taint = false };
            const lwe_key = Toy.lweKeyGen(64, clean1.io());
            const glwe_key = Toy.glweKeyGen(clean2.io());

            var mu: T = Toy.encodeBit(1);
            taintBytes(T, tainted, &mu);
            const mu_loaded = reloadVolatile(T, &mu);
            var enc1: SyntheticIo = .{ .inner = base_io, .taint = false };
            const lwe_ct = Toy.lweEncrypt(64, &lwe_key, mu_loaded, enc1.io());

            var msg = Toy.Poly.zero();
            for (&msg.c, 0..) |*c, i| c.* = Toy.encodeBit(@intCast(i & 1));
            taintBytes(Toy.Poly, tainted, &msg);
            const msg_loaded = reloadVolatile(Toy.Poly, &msg);
            var enc2: SyntheticIo = .{ .inner = base_io, .taint = false };
            const glwe_ct = Toy.glweEncrypt(&glwe_key, &msg_loaded, enc2.io());

            std.debug.print("ctgrind_result[0]={x} ctgrind_result[1]={x}\n", .{
                std.mem.toBytes(lwe_ct.b),
                std.mem.toBytes(glwe_ct.b.c[0]),
            });
        },

        // REAL key and REAL ciphertext, both off untainted entropy; only
        // the secret key is tainted, just before the decrypt call.
        .decrypt => {
            var clean1: SyntheticIo = .{ .inner = base_io, .taint = false };
            var clean2: SyntheticIo = .{ .inner = base_io, .taint = false };
            const real_lwe_key = Toy.lweKeyGen(64, clean1.io());
            const real_glwe_key = Toy.glweKeyGen(clean2.io());

            var enc1: SyntheticIo = .{ .inner = base_io, .taint = false };
            const lwe_ct = Toy.lweEncrypt(64, &real_lwe_key, Toy.encodeBit(1), enc1.io());
            var msg = Toy.Poly.zero();
            msg.c[0] = Toy.encodeBit(1);
            var enc2: SyntheticIo = .{ .inner = base_io, .taint = false };
            const glwe_ct = Toy.glweEncrypt(&real_glwe_key, &msg, enc2.io());

            var lwe_key = real_lwe_key;
            var glwe_key = real_glwe_key;
            taintBytes(Toy.LweKey(64), tainted, &lwe_key);
            taintBytes(Toy.GlweKey, tainted, &glwe_key);
            const lwe_key_loaded = reloadVolatile(Toy.LweKey(64), &lwe_key);
            const glwe_key_loaded = reloadVolatile(Toy.GlweKey, &glwe_key);

            const bit = Toy.lweDecryptBit(64, &lwe_key_loaded, &lwe_ct);
            const phase = Toy.glwePhase(&glwe_key_loaded, &glwe_ct);
            std.debug.print("bit={} ctgrind_result={x}\n", .{ bit, std.mem.toBytes(phase.c[0]) });
        },

        // Taints BOTH the LWE and GLWE secret keys entering
        // bootstrapKeyGen/keySwitchKeyGen (with REAL, untainted entropy for
        // those functions' own row-masking draws), then drives the REAL
        // bootstrap. The ciphertext under test is built from an UNTAINTED
        // copy of the SAME key, so a_tilde/b_tilde (blindRotate's rotation
        // exponents) stay public throughout -- see module doc comment.
        .bootstrap => {
            var clean1: SyntheticIo = .{ .inner = base_io, .taint = false };
            var clean2: SyntheticIo = .{ .inner = base_io, .taint = false };
            const real_lwe_key = Toy.lweKeyGen(64, clean1.io());
            const real_glwe_key = Toy.glweKeyGen(clean2.io());

            var lwe_key_for_keys = real_lwe_key;
            var glwe_key_for_keys = real_glwe_key;
            taintBytes(Toy.LweKey(64), tainted, &lwe_key_for_keys);
            taintBytes(Toy.GlweKey, tainted, &glwe_key_for_keys);
            const lwe_key_loaded = reloadVolatile(Toy.LweKey(64), &lwe_key_for_keys);
            const glwe_key_loaded = reloadVolatile(Toy.GlweKey, &glwe_key_for_keys);

            var bsk_src: SyntheticIo = .{ .inner = base_io, .taint = false };
            const bsk = Toy.bootstrapKeyGen(&lwe_key_loaded, &glwe_key_loaded, bsk_src.io());
            var ksk_src: SyntheticIo = .{ .inner = base_io, .taint = false };
            const ksk = Toy.keySwitchKeyGen(&glwe_key_loaded, &lwe_key_loaded, ksk_src.io());

            // The ciphertext under test: encrypted under the REAL,
            // untainted key and REAL entropy, so a_tilde/b_tilde are public
            // data never touched by this target's taint.
            const lut = identityLut();
            var ct_src: SyntheticIo = .{ .inner = base_io, .taint = false };
            const ct = Toy.lweEncrypt(64, &real_lwe_key, Toy.encodeBit(1), ct_src.io());
            const out = Toy.bootstrap(&bsk, &ksk, &lut, &ct);

            // Propagation proof: decrypt under the REAL key (the output
            // ciphertext itself carries the taint from bsk/ksk, through
            // blindRotate+keySwitch).
            const bit = Toy.lweDecryptBit(64, &real_lwe_key, &out);
            // ⛔ `bit` alone is ONE BIT, which no output pin can read: it cannot
            // distinguish "bootstrap computed something else" from "the harness
            // never ran it". The output ciphertext is the actual result of the
            // call under test and carries the bsk/ksk taint, so print that too.
            std.debug.print("bootstrap bit={} ctgrind_result={x}\n", .{
                bit,
                std.mem.sliceAsBytes(out.a[0..]),
            });
        },
    }
}

// ── suggested scripts/ctgrind.sh entries (coordinator wires these) ─────────
//
// ⚠⚠ `run_one`'s valgrind invocation needs `--max-stackframe=16777216` added
// for `tfhe` specifically (see trap 3 above) -- wiring TARGETS/MODES/PATTERN
// below WITHOUT that flag reproduces this pass's ~7000-error false-positive
// flood on every single row, on every target including `keygen`.
//
// declare -A TARGETS+=( [tfhe]="keygen encrypt decrypt bootstrap" )
// declare -A MODES+=(   [tfhe]="ReleaseFast" )
// declare -A PATTERN+=(
//     [tfhe/keygen]='tfhe[.]zig'
//     [tfhe/encrypt]='tfhe[.]zig'
//     [tfhe/decrypt]='tfhe[.]zig|torus[.]zig|poly[.]zig|ntt[.]zig'
//     [tfhe/bootstrap]='tfhe[.]zig|gadget[.]zig|poly[.]zig|torus[.]zig|ntt[.]zig'
// )
// declare -A LABEL+=(
//     [tfhe/keygen]='tfhe lweKeyGen/glweKeyGen sampleBit (RNG entropy)'
//     [tfhe/encrypt]='tfhe lweEncrypt/glweEncrypt plaintext mu/msg'
//     [tfhe/decrypt]='tfhe lweDecryptBit/lwePhase/glwePhase secret key -> ntt.zig ring mul'
//     [tfhe/bootstrap]='tfhe bootstrap: blindRotate+cmux+externalProduct+keySwitch, bsk/ksk from tainted LWE+GLWE key'
// )
// No per-module WITNESS override needed -- the global `Writer[.]zig|Format[.]zig|fmt[.]zig`
// already covers this harness's `std.debug.print` propagation-proof calls.
// ⚠ `bootstrap`'s claim row hits memcheck's own 10-million-error cap
// ("More than 10000000 total errors detected. I'm not reporting any more.")
// -- `scripts/ctgrind.sh`'s existing `log_hit_error_limit`/`accounted=2`
// convention for a truncated log already covers this; it needs no new code,
// only for whoever reads the row to expect `accounted=2`, not 1.
