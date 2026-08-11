// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant-time
//! check" section, as an actual committed program instead of a code block a
//! reader has to retype. Run it through `scripts/ctgrind-ct25519.sh`, which
//! builds every mode/switch/taint combination and prints the control table;
//! that script's header has the exact commands. This file is deliberately
//! NOT wired into `zig build test-ct25519` — memcheck's context count is
//! valgrind's own output, not something a Zig test can observe, so there is
//! nothing for the ordinary test runner to assert on. It exists to be run
//! under valgrind by name, not to rot as an unbuilt recipe.
//!
//! ## What this measures
//!
//! `voprf` calls exactly two ct25519 entry points for every SECRET scalar
//! (`skS`, the client `blind` and its inverse, POPRF's `t`/`t_inv`, the DLEQ
//! nonce `r` — nine call sites, `modules/voprf/src/root.zig`):
//! `mulRistrettoBase` and `mulRistretto`. Both bottom out in this module's
//! `mul`, so tainting a scalar and driving it through `mulRistrettoBase`
//! exercises the same ladder + `pcSelect` + `precompute` code voprf relies
//! on. `--target=std` runs the SAME tainted scalar through
//! `std.crypto.ecc.Ristretto255.mul` instead — the function `ct25519` exists
//! to replace — as the negative control: `SPEC.md`'s narrative claim is that
//! std's ladder has a real branch on the scalar (`rejectIdentity`'s
//! `if (p.x.isZero())`) where this module has none, and that claim is only
//! evidence if the std run actually reports a nonzero count under the exact
//! same harness.
//!
//! ## The two traps (see `chachapoly`'s `poly1305.zig` for the same shape)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, and the release
//!    optimize modes default that off. Built WITHOUT `-fvalgrind`, every
//!    client request compiles to nothing and `--taint=yes` silently behaves
//!    like `--taint=no` — a clean run that measures nothing. The driver
//!    script builds both ways so this shows up as its own row, not as a
//!    silent false clean.
//! 2. An optimizer is in principle free to keep a defined copy of the scalar
//!    in a register (or to CSE the multiply against a spilled copy from
//!    before `makeMemUndefined` ran), so the ladder would never read the
//!    memory that was marked and the whole table would read zero for the
//!    wrong reason. `reloadVolatile` below forces one real load from
//!    freshly-tainted memory immediately before the call under test.
//!    ⚠ Unlike trap 1, this one is **defensive, not demonstrated**: replacing
//!    `reloadVolatile` with a plain `return s.*` reproduces all six rows of
//!    the table byte-identically on zig 0.16.0 / x86_64 / ReleaseFast
//!    (measured 2026-08-11). It is insurance against a codegen change, and
//!    stating it as an observed requirement would be a claim this harness
//!    cannot back — which is the exact failure this file exists to end.
//!
//! ## The propagation proof
//!
//! A zero count in the code under test is only meaningful if the taint
//! reached somewhere observable — otherwise "zero" and "never touched" look
//! identical. After the call, this harness formats the result through
//! `std.debug.print`, which is NOT constant-time (digit/hex formatting
//! branches on the value it is printing). That print's contexts are
//! reported separately from the target's own contexts: seeing them nonzero
//! is what proves the taint travelled scalar -> point -> stdout, so a zero
//! count inside `ct25519`'s own code means "no branch found", not "taint
//! never arrived".

const std = @import("std");
const builtin = @import("builtin");
const ct25519 = @import("root.zig");
const Ristretto255 = std.crypto.ecc.Ristretto255;

/// Deterministic "random" scalar, reduced mod L so it is valid input to both
/// ladders. Computed at runtime (not folded at comptime) so tainting it
/// actually marks the memory the ladder reads. Not a KAT — this is a
/// diagnostic tool, not a correctness test, and a fixed seed just keeps
/// repeated runs of the table comparable.
fn secretScalar() [32]u8 {
    const msg = "ctgrind-ct25519-harness-secret-scalar-v1";
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(msg, &wide, .{});
    return Ristretto255.scalar.reduce64(wide);
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the ladder cannot be fed a copy that predates
/// `makeMemUndefined` — see trap 2 above, including the measurement showing
/// this is precaution rather than an observed requirement on today's
/// compiler.
fn reloadVolatile(s: *const [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { ct25519, std_mul };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "ct25519")) return .ct25519;
    if (std.mem.eql(u8, s, "std")) return .std_mul;
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
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var s = secretScalar();
    if (taint == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&s);
    }
    const sec = reloadVolatile(&s);

    // The call under test. `mulRistrettoBase` is what all nine voprf secret
    // call sites reduce to (base-point form for `skS`/`t`; `mulRistretto`
    // against a runtime point for `blind`/`blind_inv`/`t_inv`/`r` -- both
    // paths share the same `mul` ladder, so exercising the base-point entry
    // point exercises the same code).
    var out_bytes: [32]u8 = undefined;
    switch (target) {
        .ct25519 => {
            const q = ct25519.mulRistrettoBase(sec);
            out_bytes = q.toBytes();
        },
        .std_mul => {
            if (Ristretto255.basePoint.mul(sec)) |q| {
                out_bytes = q.toBytes();
            } else |err| {
                // Reachable only if `sec` happens to reduce to 0 mod L,
                // which the fixed seed above does not. Handled anyway so a
                // future seed change fails loudly instead of silently
                // skipping the call under test.
                std.debug.print("std mul rejected: {t}\n", .{err});
                return err;
            }
        },
    }

    // Propagation proof: format the (tainted, if taint=yes) result through a
    // non-constant-time path. See the module doc comment above.
    std.debug.print("result={x}\n", .{out_bytes});
}
