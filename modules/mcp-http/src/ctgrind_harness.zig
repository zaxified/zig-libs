// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh mcp-http`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-mcp-http`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `sid` — the 16 random bytes of an `Mcp-Session-Id` tainted through
//!    `sidhex.encode`, the exact routine `Sessions.create` runs on its
//!    CSPRNG draw (`create` itself draws from the OS, so its bytes cannot be
//!    tainted from outside). Until 2026-10-10 `create` formatted them with
//!    `std.fmt` `{x}`, a digit table indexed by the secret nibble.
//!
//! The registry lookup of a presented id (a hash map) is not measured, the
//! same choice as `sessions`' store lookup.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const sidhex = @import("sidhex.zig");

const Target = enum { sid };
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
        .sid => {
            var raw: [16]u8 = undefined;
            std.crypto.hash.Blake3.hash("ctgrind-mcp-http-sid-v1", &raw, .{});
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            var text: [32]u8 = undefined;
            sidhex.encode(&text, &raw);
            std.debug.print("ctgrind_result={x}\n", .{text});
        },
    }
}
