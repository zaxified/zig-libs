// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant
//! time" section, which claims: "`genWithSeeds`, `eval`, `evalFull`/
//! `evalFullWith` and `Mpf`'s interleaved walk no longer branch on a secret
//! bit. The α path bit in Gen and the running control bit `t` in every
//! evaluator drive XOR-masked selects (`selectSeed`, `selectBit`,
//! `xorMasked` in `dpf.zig`), so the instruction and branch trace is
//! identical for every key, every α and every control-bit pattern." Until
//! this file, that sentence was asserted in prose and never run under an
//! instrument. `fss` has no per-module block in `scripts/ctgrind.sh` yet
//! (see the suggested wiring at the bottom of this comment), so drive it by
//! hand:
//!
//!     zig build ctgrind -Dctgrind-module=fss -Dctgrind-valgrind=true  -Doptimize=ReleaseFast
//!     zig build ctgrind -Dctgrind-module=fss -Dctgrind-valgrind=false -Doptimize=ReleaseFast
//!     valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!         zig-out/ctgrind/ctgrind-fss <target> <yes|no>
//!
//! ⛔⛔ `-Doptimize=ReleaseFast` is not optional — Debug builds tens of
//! thousands of meaningless overflow-check branches on every masked select
//! below and buries the real question in noise (see `scripts/ctgrind.sh`'s
//! header, § MODES, for the measured Debug/ReleaseFast attribution gap).
//!
//! ## What this measures, and why THIS module
//!
//! `fss` (Function Secret Sharing) exists specifically to hide a secret
//! domain index α behind masked selects that, before this harness, had never
//! been run under an instrument that can tell a real branch from a select.
//! The property under test IS the module's reason to exist, not incidental
//! hardening bolted onto something else.
//!
//! Two targets, matching the two Fable-irreducible entry points named in
//! `dpf.zig`'s own module doc ("Fable-irreducible core"):
//!
//!   - `gen`  — taints α (the domain index `genWithSeeds` hides) and the two
//!     caller-supplied root seeds `s0`/`s1`, then drives them through
//!     `Dpf(n,L).genWithSeeds`. `β` (the output-group payload) is left
//!     untainted: the task that specified this harness scoped the taint to
//!     "α (and the DPF seeds)" only, not to every secret-shaped input.
//!   - `eval` — first builds a REAL key from a FIXED, untainted α/seeds (this
//!     call is setup, not the code under test), then taints the ENTIRE
//!     resulting `Key` — `seed`, every level's `cw`, and `cw_final` — before
//!     calling `.eval` on it. All of a `Key`'s bytes are what the
//!     reconstruction game hides α (and β) behind, and a real Eval party's
//!     key IS its whole secret input, so partial-tainting it (e.g. `cw` but
//!     not `seed`) would understate what the party actually holds. The
//!     evaluation point `x` and the party index `b` are left untainted
//!     throughout: `x` is the adversary-chosen PUBLIC query this harness must
//!     NOT taint (per the task briefing), and `b` is public per-party
//!     bookkeeping, not part of the hidden `(α,β)`.
//!
//! Both targets use the DEFAULT instantiation, `Dpf(n,L)` = `DpfWith(prg.
//! default, n, L)` = fixed-key AES-128 (`prg.Aes128Mmo`) — because that is
//! the type the public API actually returns and what `SPEC.md`'s "Constant
//! time" section is stated about. Every run prints
//! `aes_hw=<prg.Aes128Mmo.constant_time>` up front: on a target WITHOUT
//! hardware AES, `std.crypto.core.aes` falls back to a T-table
//! implementation whose indices depend on the data, and that is `prg.zig`'s
//! OWN, already-documented, non-`dpf.zig` caveat (see `prg.zig`'s module doc
//! and `SPEC.md`'s "Constant time" section) — not a new finding. This
//! harness's claim is about `dpf.zig`'s tree; see the suggested `PATTERN`
//! below for how that is kept separate from the PRG's own story.
//!
//! ## The two traps (same shape as every other harness in this collection)
//!
//! 1. `-fvalgrind` trap — release optimize modes default
//!    `builtin.valgrind_support` off, so a binary built without the switch
//!    silently measures nothing: `makeMemUndefined` compiles to nothing and
//!    a "clean" row means "the switch was off", not "no branch found". Build
//!    both ways; the no-switch run is its own row (the "trap" row), not
//!    assumed clean.
//! 2. Optimizer trap — a defined copy could in principle survive a
//!    register/CSE past `makeMemUndefined`. `reloadVolatile` below forces
//!    one real byte-by-byte load from freshly-tainted memory immediately
//!    before the call under test, for every tainted value (α, `s0`, `s1` for
//!    `gen`; the whole `Key` for `eval`). This is precaution, not a
//!    demonstrated requirement on today's compiler — see ct25519's harness
//!    for the measurement establishing that on zig 0.16.0/x86_64/
//!    ReleaseFast this is currently belt-and-braces.
//!
//! ## The propagation proof
//!
//! After the call under test, this harness formats part of the result
//! (`gen`'s `cw_final` for both parties; `eval`'s output share) through
//! `std.debug.print`, which is NOT constant time by design (digit/hex
//! formatting branches on the value). Seeing THAT print's contexts nonzero is
//! what proves the taint actually reached the output — so a zero count
//! inside `dpf.zig` itself means "no branch found", not "taint never
//! arrived".
//!
//! ## Suggested `scripts/ctgrind.sh` wiring (`fss` has no block there yet)
//!
//!     TARGETS[fss]="gen eval"
//!     MODES[fss]="ReleaseFast"
//!     PATTERN[fss/gen]='dpf[.]zig|group[.]zig'
//!     PATTERN[fss/eval]='dpf[.]zig|group[.]zig'
//!     LABEL[fss/gen]='fss genWithSeeds (alpha,s0,s1)'
//!     LABEL[fss/eval]='fss eval (key)'
//!
//! `prg[.]zig` and std's AES core are deliberately NOT in the suggested
//! pattern: the claim under test is `dpf.zig`'s tree, and `prg.zig`'s own
//! constant-time story is hardware-AES-conditional and separately documented
//! (see above). If a run's total does not equal in-file+witness on a target
//! that lacks hardware AES, that is `prg.zig`'s known caveat surfacing
//! through `unattr`, not a bug in this harness's classification — widen
//! `--pattern` with `aes[.]zig|core[.]zig` to confirm before treating it as
//! new.

const std = @import("std");
const builtin = @import("builtin");
const fss = @import("root.zig");

/// Domain `{0,1}^8` (256 points), output group `Z_{2^32}` — small enough to
/// keep the per-run PRG-call count trivial under memcheck, while still
/// walking `genWithSeeds`/`eval`'s full 8-level loop per call.
const n_bits = 8;
const out_bytes = 4;
const D = fss.Dpf(n_bits, out_bytes);

/// Forces one real load of every byte of `v` through a volatile pointer, so
/// the code under test cannot be fed a copy that predates `makeMemUndefined`
/// — see trap 2 above. Generic over any fixed-layout, pointer-free `T`
/// (integers, byte arrays, and `D.Key`, none of which contain pointers or
/// slices).
fn reloadVolatile(comptime T: type, v: *const T) T {
    var out: T = undefined;
    const src = std.mem.asBytes(v);
    const dst = std.mem.asBytes(&out);
    for (dst, src) |*d, *s| {
        const vs: *const volatile u8 = s;
        d.* = vs.*;
    }
    return out;
}

/// Deterministic "random" α, reduced into the 8-bit domain. Computed at
/// runtime (not folded at comptime) so tainting it actually marks memory the
/// harness reads. Not a KAT — a diagnostic tool, not a correctness test.
fn secretAlpha() D.Index {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-fss-harness-secret-alpha-v1", &digest, .{});
    return @truncate(std.mem.readInt(u32, digest[0..4], .little));
}

/// Deterministic "random" root seed pair for `genWithSeeds`. Two SHA-512
/// halves so `s0 != s1`, which the real protocol requires (independent
/// per-party randomness).
fn secretSeeds() struct { s0: fss.prg.Seed, s1: fss.prg.Seed } {
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("ctgrind-fss-harness-secret-seeds-v1", &wide, .{});
    return .{ .s0 = wide[0..16].*, .s1 = wide[16..32].* };
}

const Target = enum { gen, eval };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "gen")) return .gen;
    if (std.mem.eql(u8, s, "eval")) return .eval;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

/// `gen` target: taint α, s0, s1 entering `genWithSeeds`. β is public.
fn runGen(taint: Taint) void {
    var alpha: D.Index = secretAlpha();
    const seeds = secretSeeds();
    var s0 = seeds.s0;
    var s1 = seeds.s1;

    if (taint == .yes) {
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&alpha));
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&s0));
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&s1));
    }
    const alpha_r = reloadVolatile(D.Index, &alpha);
    const s0_r = reloadVolatile(fss.prg.Seed, &s0);
    const s1_r = reloadVolatile(fss.prg.Seed, &s1);

    const beta: D.Elem = 0xDEADBEEF; // public payload; out of this harness's taint scope

    const keys = D.genWithSeeds(alpha_r, beta, s0_r, s1_r);

    // Propagation proof: format (tainted-if-yes) output through a
    // non-constant-time path.
    // ⚠ Printed through `std.mem.toBytes`, not as `{x}` on the integer: `{x}`
    // drops leading zeros, so a small `cw_final` would print fewer hex digits
    // than the output pin's floor and the pin would appear and disappear with
    // the VALUE rather than with the code. Bytes are always fixed width.
    std.debug.print(
        "gen ctgrind_result[0]={x} ctgrind_result[1]={x}\n",
        .{ std.mem.toBytes(keys[0].cw_final), std.mem.toBytes(keys[1].cw_final) },
    );
}

/// `eval` target: build a REAL key from FIXED, untainted α/seeds (setup, not
/// under test), then taint the WHOLE key before calling `.eval` on a fixed,
/// untainted, public `x`.
fn runEval(taint: Taint) void {
    const fixed_alpha: D.Index = 173;
    const fixed_beta: D.Elem = 0x01020304;
    const fixed_s0: fss.prg.Seed = [_]u8{0x11} ** 16;
    const fixed_s1: fss.prg.Seed = [_]u8{0x22} ** 16;
    const keys = D.genWithSeeds(fixed_alpha, fixed_beta, fixed_s0, fixed_s1);
    var key = keys[0];

    if (taint == .yes) {
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&key));
    }
    const key_r = reloadVolatile(D.Key, &key);

    // `x`: the adversary-chosen PUBLIC query point. Deliberately NOT
    // tainted — see the module doc comment and the task that specified this
    // harness. `b` (party index) is likewise public.
    const x: D.Index = 42;
    const share = D.eval(0, key_r, x);

    std.debug.print("eval ctgrind_result={x}\n", .{std.mem.toBytes(share)});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} aes_hw={}\n", .{ builtin.valgrind_support, fss.prg.Aes128Mmo.constant_time });

    switch (target) {
        .gen => runGen(taint),
        .eval => runEval(taint),
    }
}
