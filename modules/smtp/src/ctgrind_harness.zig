// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh smtp`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-smtp`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `auth` — the password tainted through `auth.plainResponse` (RFC 4616
//!    `authzid NUL authcid NUL passwd`, base64) and `auth.loginResponse`
//!    (AUTH LOGIN's base64 of the password), at password lengths that hit
//!    each base64 tail (0, 1 and 2 leftover bytes). Usernames and lengths are
//!    public. Until 2026-10-10 the credential went through std's base64
//!    encoder (an alphabet table indexed by the secret) and a per-byte
//!    branching NUL/CR/LF check; `b64ct.zig` and a masked check replaced both.
//!
//! SMTP has no other secret: TLS is the `tlsclient` module's.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const smtp = @import("root.zig");

const Target = enum { auth };
const Taint = enum { yes, no };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    switch (target) {
        .auth => {
            var pw = "correct horse battery staple!!".*; // 30 bytes
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&pw);
            var buf: [256]u8 = undefined;
            for ([_]usize{ 30, 29, 28 }) |n| {
                const p = try smtp.auth.plainResponse(&buf, "", "alice@example.com", pw[0..n]);
                std.debug.print("ctgrind_result={x}\n", .{p});
                const l = try smtp.auth.loginResponse(&buf, pw[0..n]);
                std.debug.print("ctgrind_result={x}\n", .{l});
            }
        },
    }
}
