// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant-time
//! contract" section, as an actual committed program. Run it through
//! `../../../scripts/ctgrind.sh montint`.
//!
//! That section closed with "**No timing audit tool has been run**" and rested
//! on one hand-read `montMul` disassembly. `scripts/ctgrind-expected.tsv` had
//! no row for `montint` and `scripts/ctgrind.sh` had no target for it. That is
//! what this closes — and it matters more here than almost anywhere else in
//! the repo, because montint `b199192` (the optimizer recovering the
//! `powMont` table gather and lowering it to a secret-indexed jump table) is
//! the leak class that `k256`, `field.zig` and `group.zig` all cite by commit
//! hash when they explain their own `blackBox` barriers.
//!
//! NOT wired into `zig build test-montint` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## The three targets, and why the modulus SIZE is the interesting axis
//!
//! `montMul`/`montSqr` dispatch on the limb count `L`, and the three branches
//! are three different bodies of code with three separate constant-time
//! claims. A harness at one size measures one of them and says nothing about
//! the other two, so each size gets a target:
//!
//! * `small` — `Modint(256)`, `L = 4`. Below both `sqr_min_limbs` (8) and
//!   `asm_min_limbs` (32), so everything routes to `montMulCios`
//!   (`montint.zig:371`) including squaring. Drives `add`, `sub`, `mul`,
//!   `montMul` and `montSqr` from tainted operands: the target for
//!   `SPEC.md`'s "`add`/`sub`: conditional add/subtract via a mask, no
//!   data-dependent branch" and for `condSubTop` (`montint.zig:485`), which
//!   every one of those ends in. This is also the size the pairing fields use
//!   (`bn254` L=4, `bls12_381` L=6), which the dispatch comment calls out as
//!   the ones that MUST stay portable.
//! * `portable` — `Modint(1024)`, `L = 16`. At/above `sqr_min_limbs`, below
//!   `asm_min_limbs`: the dedicated portable square `montSqrCios`
//!   (`montint.zig:281`) is live, and the asm core is not. Drives `powMont`
//!   with a tainted EXPONENT and a tainted base — the flagship claim
//!   (`montint.zig:417`): fixed 5-bit window, a multiply per window, a
//!   branchless 32-entry gather, all `L·64` exponent bits processed.
//! * `asm` — `Modint(2048)`, `L = 32`. At `asm_min_limbs`, so `montMul` and
//!   `montSqr` route into `asm_core.montMul`/`montSqr`
//!   (`asm_core.zig:47`: "no secret-dependent branch, load address, or
//!   store address"). Same tainted `powMont`, so the same window/gather logic
//!   runs on top of the asm core. Memcheck reads real machine code, so the
//!   inline-asm block is measured exactly like compiled Zig: a `Jcc` on a
//!   tainted flag or a tainted address would both be reported.
//!
//! ## What the counts mean
//!
//! All three targets are expected to report **zero** in-module contexts. That
//! zero is only readable because the total is non-zero: the results are
//! printed through `std.debug.print`, which is not constant-time, so a tainted
//! byte reaching the formatter always produces contexts of its own. A zero
//! in-file count next to a zero total would mean "the taint never arrived",
//! which is what the `total_min` column in `scripts/ctgrind-expected.tsv`
//! exists to rule out.
//!
//! ## What this harness does NOT pin (an honest gap)
//!
//! * `limbs.cmp` (`limbs.zig:45`, "Constant-time comparison … no
//!   secret-dependent branch or early exit"). Every limb IS inspected — but
//!   the function then returns `std.math.Order`, i.e. the comparison result
//!   itself, via `if (lt == 1) return .lt;`. Any caller that uses the answer
//!   branches on it. Tainting an input to `cmp` therefore reports a context by
//!   construction, and that context is the function's return value, not a
//!   leak: the claim `cmp` makes is about the SCAN (no early exit), which is a
//!   statement about which limbs are read, and memcheck cannot distinguish
//!   "read all limbs then branch once" from "branch early" — both are one
//!   context. So `cmp` is not driven from tainted data here, and its
//!   no-early-exit property remains backed by reading the loop, not by
//!   measurement. Its one production caller, `elementFromBytesBE`, compares a
//!   caller-supplied encoding against the PUBLIC modulus and is a validation
//!   that returns `error.NonCanonical` — a branch it must take by contract.
//! * `Modint.bits()` walks limbs with an early `if (self.m[i-1] != 0) return`,
//!   over the PUBLIC modulus. Never a secret.
//! * `limbs.mulSchoolbook` / `mulKaratsuba` carry no constant-time claim
//!   (`mulKaratsuba` is documented as a correctness anchor for a deferred SOS
//!   path); they are not on the `montMul` dispatch.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind`, `std.valgrind.doClientRequest` returns early
//!    (`builtin.valgrind_support` is off outside Debug) and every row reads 0
//!    regardless. The driver builds both ways and prints it as a row.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory so the
//!    optimizer cannot feed the code under test a defined register copy.
//!    Defensive, not demonstrated.
//! 3. ReleaseFast only. `Debug`/`ReleaseSafe` add integer-overflow checks to
//!    the `u128` limb arithmetic, which are branches on tainted values and
//!    bury the signal.
//! 4. The modulus is a PUBLIC value and is deliberately never tainted —
//!    `computeConstants` does `128·L` `doubleMod`s over it at construction,
//!    and a tainted modulus would report those as the modulus's own
//!    `condSubTop`, which is not a claim anyone makes.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Modint = root.Modint;

/// Deterministic secret material. Computed at runtime (not folded at comptime)
/// so tainting it marks memory the code under test actually reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// A PUBLIC odd modulus of exactly `L` limbs, derived deterministically. Its
/// top bit is set so the value really is `max_bits` wide (a short modulus would
/// silently shrink the work), and its low bit is set so it is odd.
fn publicModulus(comptime M: type, comptime domain: []const u8) M.Elem {
    const raw = secretBytes(8 * M.L, domain);
    var v: M.Elem = undefined;
    for (&v, 0..) |*w, i| w.* = std.mem.readInt(u64, raw[i * 8 ..][0..8], .little);
    v[0] |= 1; // odd
    v[M.L - 1] |= @as(u64, 1) << 63; // full width
    return v;
}

/// Tainted secret limbs, forced through a volatile reload. Reduced below the
/// modulus by masking the top bit rather than comparing, so the harness does
/// not itself branch on the secret before the code under test sees it (the
/// modulus built above always has that bit set, so clearing it in the value
/// guarantees `v < m` with no comparison at all).
fn secretElem(comptime M: type, comptime domain: []const u8, tainted: bool) M.Elem {
    var raw = secretBytes(8 * M.L, domain);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(&raw);
    const r = reloadVolatile(8 * M.L, &raw);
    var v: M.Elem = undefined;
    for (&v, 0..) |*w, i| w.* = std.mem.readInt(u64, r[i * 8 ..][0..8], .little);
    v[M.L - 1] &= ~(@as(u64, 1) << 63);
    return v;
}

fn printElem(comptime M: type, name: []const u8, m: *const M, v: *const M.Elem) void {
    var out: [M.encoded_bytes]u8 = undefined;
    m.toBytesBE(v, &out);
    // Hex formatting is not constant-time: this is the propagation witness.
    std.debug.print("{s}={x}\n", .{ name, out });
}

const Target = enum { small, portable, asmcore };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "small")) return .small;
    if (std.mem.eql(u8, s, "portable")) return .portable;
    if (std.mem.eql(u8, s, "asmcore")) return .asmcore;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

/// `powMont` on a tainted base and a tainted exponent, at the given width.
fn runPow(comptime bits: comptime_int, comptime tag: []const u8, tainted: bool) !void {
    const M = Modint(bits);
    const m = try M.fromElem(publicModulus(M, "ctgrind-montint-harness-modulus-" ++ tag ++ "-v1"));
    std.debug.print("L={d} dispatches_to_asm={}\n", .{ M.L, M.dispatchesToAsm() });

    const base = secretElem(M, "ctgrind-montint-harness-base-" ++ tag ++ "-v1", tainted);
    const exp = secretElem(M, "ctgrind-montint-harness-exponent-" ++ tag ++ "-v1", tainted);

    const r = m.powMont(&base, &exp);
    printElem(M, "pow", &m, &r);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={} asm_active={}\n", .{
        builtin.valgrind_support,
        root.asm_active,
    });

    switch (target) {
        .small => {
            // L = 4: below both dispatch cutoffs, so `montSqr` folds into
            // `montMulCios(a, a)` and nothing asm runs. Exercises the modular
            // add/sub masks and the normal-domain `mul` on top of that.
            const M = Modint(256);
            const m = try M.fromElem(publicModulus(M, "ctgrind-montint-harness-modulus-small-v1"));
            std.debug.print("L={d} dispatches_to_asm={}\n", .{ M.L, M.dispatchesToAsm() });

            const a = secretElem(M, "ctgrind-montint-harness-a-small-v1", tainted);
            const b = secretElem(M, "ctgrind-montint-harness-b-small-v1", tainted);

            const sum = m.add(&a, &b);
            const dif = m.sub(&a, &b);
            const prod = m.mul(&a, &b);
            const am = m.toMontgomery(&a);
            const sqm = m.montSqr(&am);
            const sq = m.fromMontgomery(&sqm);

            printElem(M, "add", &m, &sum);
            printElem(M, "sub", &m, &dif);
            printElem(M, "mul", &m, &prod);
            printElem(M, "sqr", &m, &sq);
        },
        .portable => try runPow(1024, "portable", tainted),
        .asmcore => try runPow(2048, "asm", tainted),
    }
}
