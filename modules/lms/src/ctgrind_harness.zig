// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh lms`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-lms`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures (LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W4)
//!
//!  * `lms` — `LmsSecretKey.init` (the whole Merkle tree from the secret
//!    seed) and two `sign`s with the seed tainted. Messages, the identifier
//!    `I`, the leaf index `q` and parameter sets are public.
//!  * `hss` — a two-level HSS `SecretKey` (both levels H5/W4) from a tainted
//!    seed and two `sign`s.
//!
//! Everything a signature contains — the OTS chain values revealed for this
//! message, the authentication path, the public key — is public once
//! published, but it is derived from the seed and therefore tainted here; a
//! branch on it would still be reported (none is expected: chain lengths
//! come from the public message digest).
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const lms = @import("root.zig");

const Target = enum { lms, hss };
const Taint = enum { yes, no };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    const gpa = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from

    var seed: [lms.n]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-lms-seed-v1", &seed, .{});
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&seed);
    const id: [lms.id_len]u8 = "ctgrind-lms-id-1".*;
    var sig: [8192]u8 = undefined;

    switch (target) {
        .lms => {
            var sk: lms.LmsSecretKey = undefined;
            try sk.init(gpa, .sha256_m32_h5, .sha256_n32_w4, id, &seed);
            defer sk.deinit();
            for ([_][]const u8{ "first message", "second message" }) |msg| {
                const s = try sk.sign(msg, &sig);
                std.debug.print("ctgrind_result={x}\n", .{s[0..64]});
            }
        },
        .hss => {
            const levels = [_]lms.Level{
                .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w4 },
                .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w4 },
            };
            var sk: lms.SecretKey = undefined;
            try sk.init(gpa, &levels, &seed, id, null);
            defer sk.deinit();
            for ([_][]const u8{ "first message", "second message" }) |msg| {
                const s = try sk.sign(msg, &sig);
                std.debug.print("ctgrind_result={x}\n", .{s[0..64]});
            }
        },
    }
}
