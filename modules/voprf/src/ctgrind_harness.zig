// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh voprf`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-voprf`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures (ristretto255-SHA512)
//!
//!  * `server` — the server key `skS` and the proof nonce tainted:
//!    `blindEvaluate` (OPRF), `blindEvaluateVerifiable` (VOPRF, DLEQ proof),
//!    `blindEvaluatePoprf` (POPRF, inverted key) and the direct `evaluate`
//!    and `evaluatePoprf`.
//!    The blinded element (from the client) and `info` are public.
//!  * `client` — the client's private input and blind scalars tainted:
//!    `blind` + `finalize`, `blind` + `finalizeVerifiable` (proof check), and
//!    `blindPoprf` + `finalizePoprf`. The server's replies are public and are
//!    marked defined after computing them from the (tainted) blinded element.
//!  * `keygen` — `deriveKeyPair` with the seed tainted (all three modes).
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const v = @import("root.zig");

const Target = enum { server, client, keygen };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

/// A valid, reduced scalar from a label (blind scalars and proof nonces).
fn scalar(label: []const u8) [v.Ns]u8 {
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(label, &wide, .{});
    var out: [v.Ns]u8 = undefined;
    v.scalarFromWideBytes(&wide, &out);
    return out;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

fn defined(x: anytype) void {
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(x));
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    const seed = secretBytes(32, "ctgrind-voprf-seed-v1");
    var kp: v.KeyPair = undefined;
    try v.deriveKeyPair(.voprf, &seed, "ctgrind", &kp);
    var kp_p: v.KeyPair = undefined;
    try v.deriveKeyPair(.poprf, &seed, "ctgrind", &kp_p);
    const info = "ctgrind info";

    switch (target) {
        .server => {
            const blinded = try v.blind(.voprf, "client input", &scalar("blind-1"));
            const blinded_p = (try v.blindPoprf("client input", info, kp_p.pk, &scalar("blind-2"))).blinded_element;
            var sk = kp.sk;
            var sk_p = kp_p.sk;
            var r = scalar("proof-r");
            taintBytes(taint, &sk);
            taintBytes(taint, &sk_p);
            taintBytes(taint, &r);
            const e0 = v.blindEvaluate(&sk, blinded);
            const ve = try v.blindEvaluateVerifiable(&sk, kp.pk, blinded, &r);
            const pe = try v.blindEvaluatePoprf(&sk_p, blinded_p, info, &r);
            var out: [v.Nh]u8 = undefined;
            try v.evaluate(.oprf, &sk, "server-side input", &out);
            var out_p: [v.Nh]u8 = undefined;
            try v.evaluatePoprf(&sk_p, "server-side input", info, &out_p);
            std.debug.print("ctgrind_result={x}\n", .{e0.toBytes() ++ ve.evaluated_element.toBytes() ++ ve.proof.toBytes()});
            std.debug.print("ctgrind_result={x}\n", .{out_p});
            std.debug.print("ctgrind_result={x}\n", .{pe.evaluated_element.toBytes() ++ pe.proof.toBytes()});
            std.debug.print("ctgrind_result={x}\n", .{out});
        },
        .client => {
            var input = secretBytes(24, "ctgrind-voprf-input-v1");
            var b1 = scalar("blind-1");
            var b2 = scalar("blind-2");
            taintBytes(taint, &input);
            taintBytes(taint, &b1);
            taintBytes(taint, &b2);
            const r = scalar("proof-r");

            // OPRF / VOPRF.
            var blinded = try v.blind(.voprf, &input, &b1);
            defined(&blinded); // sent to the server
            var ve = try v.blindEvaluateVerifiable(&kp.sk, kp.pk, blinded, &r);
            defined(&ve); // the server's reply
            var out: [v.Nh]u8 = undefined;
            try v.finalize(&input, &b1, ve.evaluated_element, &out);
            std.debug.print("ctgrind_result={x}\n", .{out});
            try v.finalizeVerifiable(&input, &b1, ve.evaluated_element, blinded, kp.pk, ve.proof, &out);
            std.debug.print("ctgrind_result={x}\n", .{out});

            // POPRF.
            var pb = try v.blindPoprf(&input, info, kp_p.pk, &b2);
            defined(&pb);
            var pe = try v.blindEvaluatePoprf(&kp_p.sk, pb.blinded_element, info, &r);
            defined(&pe);
            try v.finalizePoprf(&input, &b2, pe.evaluated_element, pb.blinded_element, pe.proof, info, pb.tweaked_key, &out);
            std.debug.print("ctgrind_result={x}\n", .{out});
        },
        .keygen => {
            var s = seed;
            taintBytes(taint, &s);
            inline for (.{ v.Mode.oprf, v.Mode.voprf, v.Mode.poprf }) |mode| {
                var k: v.KeyPair = undefined;
                try v.deriveKeyPair(mode, &s, "ctgrind", &k);
                std.debug.print("ctgrind_result={x}\n", .{k.sk ++ k.pk.toBytes()});
            }
        },
    }
}
