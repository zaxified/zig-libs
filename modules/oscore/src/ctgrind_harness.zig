// SPDX-License-Identifier: MIT
//! ctgrind harness for `oscore` — the instrument for the sentence `SPEC.md`
//! § "Threat model / limits" already states:
//!
//!   "deriveKey/protect/unprotect handle secret key material ... and MUST
//!    route it only through std.crypto's own constant-time HMAC/AES-CCM
//!    implementations — no comparison or branch on key bytes anywhere in this
//!    module's own code."
//!
//! Until 2026-09-08 that sentence had no measurement behind it (audit F8).
//!
//! Usage: ctgrind-oscore <target> <yes|no>
//!   targets: derive | protect | unprotect
//!
//! ## Why every target PRINTS its result
//!
//! An earlier probe used `doNotOptimizeAway` and reported `derive` and
//! `protect` as zero contexts out of a zero total. That is not a result: a
//! total of zero means the taint never reached anything at all, which is
//! exactly what a harness that fails to call the module would report. The
//! formatting path is not constant-time by design, so a tainted byte arriving
//! there is the propagation witness that makes an in-file zero mean "no branch
//! found" rather than "nothing happened".
//!
//! ## What is tainted, per target
//!
//! `derive` taints the master secret; `protect` the derived Sender Key;
//! `unprotect` the derived Recipient Key. The IDs, the partial IV and the
//! option bytes stay public, because they are — tainting them would
//! manufacture contexts that say nothing about key handling.
//!
//! ## ReleaseFast only
//!
//! The safety checks of the other modes turn std's AES-CCM and HMAC
//! arithmetic into overflow branches on secret-derived values and flood the
//! report; and Debug cannot be measured at all, because valgrind's DWARF
//! reader cannot parse what Zig's self-hosted backend emits and Debug is the
//! only mode where that backend is the default (`scripts/checks/ctgrind.sh` § MODES).

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// Force a volatile reload so the optimizer cannot keep a defined register
/// copy of a value we have just marked undefined.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const t = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target });

    // A standalone measurement program has no caller to take an allocator from,
    // and nothing here is reachable from `oscore`'s published surface.
    const gpa = std.heap.smp_allocator; // global-alloc-ok: standalone ctgrind harness, not module code and not on the published surface
    var master: [16]u8 = [_]u8{0x42} ** 16;
    const salt: [8]u8 = [_]u8{0x9e} ** 8;

    if (std.mem.eql(u8, target, "derive")) {
        taint(t, master[0..]);
        const ms = reloadVolatile(16, &master);
        const ctx = try root.deriveContext(gpa, &ms, &salt, null, "cl", "sv", .aes_ccm_16_64_128);
        // The derived keys ARE the secret this target is about, so printing
        // them is both the witness and the value `--check` pins.
        std.debug.print("sk={x} rk={x}\n", .{ ctx.sender.key, ctx.recipient.key });
        return;
    }

    var ctx = try root.deriveContext(gpa, &master, &salt, null, "cl", "sv", .aes_ccm_16_64_128);
    var rx = try root.deriveContext(gpa, &master, &salt, null, "sv", "cl", .aes_ccm_16_64_128);
    const aad = root.AadParams{ .request_kid = "cl", .request_piv = &.{0} };
    const pt = "\x01\xffGET /sensor/temperature";

    if (std.mem.eql(u8, target, "protect")) {
        taint(t, ctx.sender.key[0..]);
        const p = try root.protect(gpa, &ctx, pt, aad, true, null);
        defer gpa.free(p.ciphertext);
        std.debug.print("ct={x}\n", .{p.ciphertext});
        return;
    }

    if (std.mem.eql(u8, target, "unprotect")) {
        const p = try root.protect(gpa, &ctx, pt, aad, true, null);
        defer gpa.free(p.ciphertext);
        taint(t, rx.recipient.key[0..]);
        const out = try root.unprotect(gpa, &rx, p.option, p.ciphertext, aad, null, true);
        defer gpa.free(out);
        std.debug.print("pt={x}\n", .{out});
        return;
    }

    return error.UnknownTarget;
}
