// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh xmss`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-xmss`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `sign` — `keyGen` and five `sign`s (exercising the BDS traversal
//!    update) with `SK_SEED` and `SK_PRF` tainted; `PUB_SEED`, messages and
//!    the index are public. Instantiated at tree height 4 (`XmssSha2(4, …)`,
//!    the same code as the registered heights with 16 leaves) so memcheck
//!    finishes in seconds; the code paths are height-generic.
//!
//! The signature's revealed WOTS chain values, authentication path and the
//! root are public once published but derived from the seed, so they are
//! tainted here too; chain lengths come from the public message digest.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const xmss = @import("root.zig");

const X = xmss.XmssSha2(4, 0xC7C7C7C7);
const Target = enum { sign };
const Taint = enum { yes, no };

fn bytes(label: []const u8) [xmss.n]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &out, .{});
    return out[0..xmss.n].*;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    switch (target) {
        .sign => {
            var sk_seed = bytes("ctgrind-xmss-sk-seed-v1");
            var sk_prf = bytes("ctgrind-xmss-sk-prf-v1");
            const pub_seed = bytes("ctgrind-xmss-pub-seed-v1");
            if (taint == .yes) {
                std.valgrind.memcheck.makeMemUndefined(&sk_seed);
                std.valgrind.memcheck.makeMemUndefined(&sk_prf);
            }
            var kp: X.KeyPair = undefined;
            X.keyGen(&kp, &sk_seed, &sk_prf, &pub_seed);
            var sig: [X.signature_length]u8 = undefined;
            for (0..5) |i| {
                var msg = "xmss message #0".*;
                msg[msg.len - 1] = '0' + @as(u8, @intCast(i));
                try X.sign(&kp.sk, &sig, &msg);
                std.debug.print("ctgrind_result={x}\n", .{sig[0..64]});
            }
        },
    }
}
