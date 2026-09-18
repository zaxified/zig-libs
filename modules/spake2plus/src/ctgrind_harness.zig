// SPDX-License-Identifier: MIT
//! ctgrind harness for `spake2plus` — the instrument for `SPEC.md`'s
//! "Constant-time discipline" and "Key-confirmation MUST be constant-time-
//! compared" bullets (§ "Threat model / security properties"):
//!
//!   "EVERY scalar multiplication in this module's cores touches SECRET
//!    material on at least one side (x, y, w0, w1 are all password- or
//!    session-derived) ... MUST all use P256's constant-time mul/add/sub,
//!    never mulPublic/mulDoubleBasePublic"
//!
//!   "a specialist implementing the stub MUST use a constant-time comparison
//!    for the received-vs-expected confirmation MAC (NOT std.mem.eql, which
//!    is variable-time)"
//!
//! `root.zig`'s own test "CT discipline: no secret multiply may use a
//! variable-time routine" already pins the SOURCE TEXT (no `mulPublic`/
//! `mulDoubleBasePublic` call site outside a comment) — see its own doc
//! comment for why that is evidence about the call site only, not about
//! whether `p256`'s `mul` itself is free of secret-dependent branches
//! (`p256` carries no `ctgrind_harness.zig` of its own; that gap is
//! recorded, not closed here). This harness is the next rung: it actually
//! runs the arithmetic under memcheck with the SECRET operands marked
//! undefined, so a branch on them — in this module's own code OR in `p256`'s,
//! since spake2plus delegates every scalar multiply to it — shows up as a
//! reported context instead of living only in a claim.
//!
//! Usage: ctgrind-spake2plus <target> <yes|no>
//!   targets: w0w1 | computel | proverstart | verifierstart | proverfinish |
//!            verifierfinish
//!
//! ## What is tainted, per target — the PASSWORD side only
//!
//! SPAKE2+ is a PAKE: the thing worth protecting here is the PASSWORD and
//! the scalars derived from it, not a 256-bit key — a password has far less
//! entropy, so a timing leak here is worth far more to an attacker than the
//! same leak on a full-entropy scalar. Every target below taints only
//! SCALARS (`w0`, `w1`, the ephemeral `x`/`y`) and NEVER the SEC1-encoded
//! GROUP ELEMENTS that actually cross the wire (`shareP`/`shareV`/`L`/`Z`/
//! `V`) — those are public by design (RFC 9383 transmits them in the clear),
//! and tainting a public value would manufacture contexts that say nothing
//! about secret handling, the same discipline `oscore`'s harness documents
//! for its IDs/partial-IV/option bytes.
//!
//!   w0w1          — taints the raw 80-byte PBKDF output (the actual
//!                   password material) entering `computeW0W1`.
//!   computel      — taints `w1` entering `computeL` (`L = w1*P`, the
//!                   registration record). ⭐ THIS is the call site the audit
//!                   already caught once: swapping this multiply for
//!                   `mulPublic` left all 29 tests green in Debug AND
//!                   ReleaseFast (root.zig, "CT discipline" test's own doc
//!                   comment) — a source-text pin cannot see a future
//!                   regression in `p256.mul` itself, only this harness can.
//!   proverstart   — taints `w0` AND the ephemeral `x` entering `proverStart`
//!                   (`X = x*P + w0*M`).
//!   verifierstart — taints `w0` AND the ephemeral `y` entering
//!                   `verifierStart` (`Y = y*P + w0*N`).
//!   proverfinish  — taints `w0`, `w1`, `x` entering `proverFinish`: the
//!                   `Z`/`V` scalar multiplies AND, on the SAME call, RFC
//!                   9383's mandatory key-confirmation check
//!                   (`std.crypto.timing_safe.eql` on `expected_confirmV` vs
//!                   `received_confirm_v` — `expected_confirmV` is tainted
//!                   because it is derived from the tainted key schedule).
//!                   This is the textbook case the instrument exists for.
//!   verifierfinish — the Verifier's mirror: taints `w0`, `y` entering
//!                   `verifierFinish`'s `Z`/`V` multiplies AND its own
//!                   `timing_safe.eql(expected_confirmP, received_confirm_p)`
//!                   check.
//!
//! ## Why every setup call stays UNTAINTED, and why that is safe
//!
//! `proverfinish`/`verifierfinish` need a REAL, matching protocol run to
//! reach the confirmation-check line at all (an early parse/range-check
//! error would return before the compare ever executes) — so this harness
//! drives the full handshake once through the module's OWN public API
//! (`computeW0W1` -> `computeL` -> `proverStart`/`verifierStart` ->
//! `verifierConfirm` -> the target function) with everything UNTAINTED,
//! and only marks the specific scalar arguments undefined immediately
//! before the ONE call under test — the same "compute a realistic value,
//! then taint a copy of it" shape `ct25519`'s harness uses for its
//! `secretScalar()`. This is also the answer to "build tainted values
//! through the module's real API, not a private helper": every scalar this
//! harness ever taints — `w0`, `w1`, `x`, `y` — is the direct output of a
//! `spake2plus.computeW0W1` call (see `deriveW0W1` below), never hand-rolled
//! scalar arithmetic living only in this file.
//!
//! ## The two traps (see `ct25519`'s harness for the measured detail)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without
//!    `-fvalgrind`, which is off by default outside Debug — a ReleaseFast
//!    binary built without the switch is a SILENT NO-OP, not a clean result.
//!    `scripts/checks/ctgrind.sh` builds both ways so this is its own trap row.
//! 2. An optimizer may keep a defined copy of a value in a register across
//!    `makeMemUndefined`, or CSE against one — `reloadVolatile` forces one
//!    real load from the just-tainted memory immediately before the call
//!    under test.
//!
//! ## ReleaseFast only
//!
//! Debug cannot be measured at all here (valgrind's DWARF reader cannot
//! parse what Zig's self-hosted backend emits, and Debug is the only mode
//! where that backend is the default — `scripts/checks/ctgrind.sh` § MODES); the
//! other safety checks (ReleaseSafe) turn `p256`'s field arithmetic and
//! std's overflow-checked limb ops into branches on secret-derived values
//! and flood the report the same way `ct25519` measured on its own ladder.

const std = @import("std");
const builtin = @import("builtin");
const spake2plus = @import("root.zig");

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// Force a volatile reload so the optimizer cannot keep a defined register
/// (or CSE'd) copy of a value we have just marked undefined — see the module
/// doc comment's trap 2.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// Deterministic 80-byte "PBKDF output" — raw entropy, computed at runtime
/// (not folded at comptime) so tainting it actually marks memory the ladder
/// reads. Not a real PBKDF; this harness only needs SOME fixed bytes to feed
/// `computeW0W1`, the module's own real entry point that turns them into
/// canonical `w0`/`w1` scalars — see the module doc comment on why nothing
/// here reimplements that reduction itself.
fn passwordBytes(label: []const u8) [80]u8 {
    var out: [80]u8 = undefined;
    var wide: [64]u8 = undefined;
    var buf: [96]u8 = undefined;
    const msg0 = std.fmt.bufPrint(&buf, "ctgrind-spake2plus-harness-v1-{s}-block0", .{label}) catch unreachable;
    std.crypto.hash.sha2.Sha512.hash(msg0, &wide, .{});
    @memcpy(out[0..64], &wide);
    const msg1 = std.fmt.bufPrint(&buf, "ctgrind-spake2plus-harness-v1-{s}-block1", .{label}) catch unreachable;
    std.crypto.hash.sha2.Sha512.hash(msg1, &wide, .{});
    @memcpy(out[64..80], wide[0..16]);
    return out;
}

/// `w0`/`w1` for a given label, ALWAYS via `spake2plus.computeW0W1` — the
/// module's real §3.2 entry point — never via private scalar arithmetic in
/// this file. Used both for the actual registration secret (label
/// "registration") and, reused as a convenient source of two independent
/// canonical scalars, for the ephemeral `x`/`y` (labels "ephemeral-x" /
/// "ephemeral-y") that a real Prover/Verifier would instead draw from a
/// CSPRNG — `computeW0W1` produces exactly the kind of value needed either
/// way: a canonical, reduced, nonzero-with-overwhelming-probability P-256
/// scalar, through public API.
fn deriveW0W1(label: []const u8) spake2plus.W0W1 {
    const pwd = passwordBytes(label);
    return spake2plus.computeW0W1(&pwd) catch unreachable; // 80 bytes by construction
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const t = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target });

    // A standalone measurement program has no caller to take an allocator
    // from, and nothing here is reachable from spake2plus's published
    // surface.
    const gpa = std.heap.smp_allocator; // global-alloc-ok: standalone ctgrind harness, not module code and not on the published surface

    if (std.mem.eql(u8, target, "w0w1")) {
        var pwd = passwordBytes("registration");
        taintBytes(t, pwd[0..]);
        const tpwd = reloadVolatile(80, &pwd);
        const w0w1 = try spake2plus.computeW0W1(&tpwd);
        std.debug.print("w0={x} w1={x}\n", .{ w0w1.w0, w0w1.w1 });
        return;
    }

    if (std.mem.eql(u8, target, "computel")) {
        const reg = deriveW0W1("registration"); // untainted setup, via computeW0W1
        var w1 = reg.w1;
        taintBytes(t, w1[0..]);
        const tw1 = reloadVolatile(32, &w1);
        const l = try spake2plus.computeL(tw1);
        std.debug.print("L={x}\n", .{l});
        return;
    }

    if (std.mem.eql(u8, target, "proverstart")) {
        const reg = deriveW0W1("registration");
        const eph_x = deriveW0W1("ephemeral-x").w0;
        var w0 = reg.w0;
        var x = eph_x;
        taintBytes(t, w0[0..]);
        taintBytes(t, x[0..]);
        const tw0 = reloadVolatile(32, &w0);
        const tx = reloadVolatile(32, &x);
        const share = try spake2plus.proverStart(tx, tw0);
        std.debug.print("X={x}\n", .{share});
        return;
    }

    if (std.mem.eql(u8, target, "verifierstart")) {
        const reg = deriveW0W1("registration");
        const eph_y = deriveW0W1("ephemeral-y").w1;
        var w0 = reg.w0;
        var y = eph_y;
        taintBytes(t, w0[0..]);
        taintBytes(t, y[0..]);
        const tw0 = reloadVolatile(32, &w0);
        const ty = reloadVolatile(32, &y);
        const share = try spake2plus.verifierStart(ty, tw0);
        std.debug.print("Y={x}\n", .{share});
        return;
    }

    // Both remaining targets need a REAL, matching protocol run to reach the
    // key-confirmation compare at all -- an early range/parse error would
    // return before that line executes. Everything below "the target under
    // test" is built through public API and stays UNTAINTED; see the module
    // doc comment's "why every setup call stays untainted" section.
    const reg = deriveW0W1("registration");
    const eph_x = deriveW0W1("ephemeral-x").w0;
    const eph_y = deriveW0W1("ephemeral-y").w1;

    const l = try spake2plus.computeL(reg.w1); // public registration record
    const share_p = try spake2plus.proverStart(eph_x, reg.w0); // X, public
    const share_v = try spake2plus.verifierStart(eph_y, reg.w0); // Y, public

    if (std.mem.eql(u8, target, "proverfinish")) {
        // The Verifier's real confirmV, so the compare below actually
        // matches and the function runs to completion instead of erroring
        // out at the ConfirmationMismatch line.
        const vconfirm = try spake2plus.verifierConfirm(gpa, "ctgrind", "prover", "verifier", reg.w0, l, eph_y, share_p, share_v);

        var w0 = reg.w0;
        var w1 = reg.w1;
        var x = eph_x;
        taintBytes(t, w0[0..]);
        taintBytes(t, w1[0..]);
        taintBytes(t, x[0..]);
        const tw0 = reloadVolatile(32, &w0);
        const tw1 = reloadVolatile(32, &w1);
        const tx = reloadVolatile(32, &x);

        const result = try spake2plus.proverFinish(
            gpa,
            "ctgrind",
            "prover",
            "verifier",
            tw0,
            tw1,
            tx,
            share_p,
            share_v,
            vconfirm.confirm_v,
        );
        defer gpa.free(result.tt);
        std.debug.print("confirmP={x} k_shared={x}\n", .{ result.confirm_p, result.k_shared });
        return;
    }

    if (std.mem.eql(u8, target, "verifierfinish")) {
        // The Prover's real confirmP, from an untainted full proverFinish
        // run, so verifierFinish's own compare below matches.
        const vconfirm = try spake2plus.verifierConfirm(gpa, "ctgrind", "prover", "verifier", reg.w0, l, eph_y, share_p, share_v);
        const pfinish = try spake2plus.proverFinish(gpa, "ctgrind", "prover", "verifier", reg.w0, reg.w1, eph_x, share_p, share_v, vconfirm.confirm_v);
        defer gpa.free(pfinish.tt);

        var w0 = reg.w0;
        var y = eph_y;
        taintBytes(t, w0[0..]);
        taintBytes(t, y[0..]);
        const tw0 = reloadVolatile(32, &w0);
        const ty = reloadVolatile(32, &y);

        const result = try spake2plus.verifierFinish(
            gpa,
            "ctgrind",
            "prover",
            "verifier",
            tw0,
            l,
            ty,
            share_p,
            share_v,
            pfinish.confirm_p,
        );
        defer gpa.free(result.tt);
        std.debug.print("confirmV={x} k_shared={x}\n", .{ result.confirm_v, result.k_shared });
        return;
    }

    return error.UnknownTarget;
}
