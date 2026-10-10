// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh dnp3`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-dnp3`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures (Secure Authentication, `sa`)
//!
//!  * `mac` — the session key tainted through `sa.mac.compute`/`verify`
//!    (every HMAC truncation and AES-GMAC) and `computeReplyMac` /
//!    `verifyReplyMac` (the challenge-reply MAC), valid and tampered tags.
//!    Messages, IVs and received tags are public.
//!  * `keys` — the update key and both session keys tainted through
//!    `wrapSessionKeys` and `unwrapSessionKeys` (AES Key Wrap, via `aeskw`),
//!    16- and 32-byte session keys, plus a tampered unwrap.
//!
//! The rest of DNP3 (link, transport, application, objects) is framing with
//! no key material.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const dnp3 = @import("root.zig");

const sa = dnp3.sa;
const Target = enum { mac, keys };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

fn verifyBoth(ok: bool, bad: bool) void {
    std.debug.print("ctgrind_result={x}\n", .{[2]u8{ @intFromBool(ok), @intFromBool(bad) }});
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
        .mac => {
            var key = secretBytes(32, "ctgrind-dnp3-session-key-v1");
            taintBytes(taint, &key);
            const msg = "DNP3 SA challenge || critical ASDU bytes";
            const iv: [12]u8 = "ctgrind-iv12".*;
            const algs = [_]sa.HmacAlgorithm{ .hmac_sha1_trunc_4, .hmac_sha1_trunc_8, .hmac_sha1_trunc_10, .hmac_sha256_trunc_8, .hmac_sha256_trunc_16, .aes_gmac_trunc_12 };
            for (algs) |alg| {
                const k: []const u8 = if (alg == .aes_gmac_trunc_12) key[0..16] else &key;
                const nonce: ?[12]u8 = if (alg == .aes_gmac_trunc_12) iv else null;
                var buf: [sa.mac.max_len]u8 = undefined;
                const tag = try sa.mac.compute(alg, k, msg, nonce, &buf);
                std.debug.print("ctgrind_result={x}\n", .{tag});
                var wire = buf;
                std.valgrind.memcheck.makeMemDefined(&wire); // received: public
                const ok = sa.mac.verify(alg, k, msg, nonce, wire[0..tag.len]);
                wire[0] ^= 1;
                verifyBoth(ok, sa.mac.verify(alg, k, msg, nonce, wire[0..tag.len]));
                if (alg == .aes_gmac_trunc_12) continue;
                const r = try sa.computeReplyMac(alg, k, "challenge", "asdu", &buf);
                std.debug.print("ctgrind_result={x}\n", .{r});
                wire = buf;
                std.valgrind.memcheck.makeMemDefined(&wire);
                const rok = sa.verifyReplyMac(alg, k, "challenge", "asdu", wire[0..r.len]);
                wire[0] ^= 1;
                verifyBoth(rok, sa.verifyReplyMac(alg, k, "challenge", "asdu", wire[0..r.len]));
            }
        },
        .keys => {
            var update = secretBytes(32, "ctgrind-dnp3-update-key-v1");
            var control = secretBytes(32, "ctgrind-dnp3-control-key-v1");
            var monitor = secretBytes(32, "ctgrind-dnp3-monitor-key-v1");
            taintBytes(taint, &update);
            taintBytes(taint, &control);
            taintBytes(taint, &monitor);
            for ([_]usize{ 16, 32 }) |kl| {
                var wrapped_buf: [72]u8 = undefined;
                const wrapped = try sa.wrapSessionKeys(&update, control[0..kl], monitor[0..kl], &wrapped_buf);
                std.debug.print("ctgrind_result={x}\n", .{wrapped});
                std.valgrind.memcheck.makeMemDefined(wrapped); // on the wire
                var out: [64]u8 = undefined;
                const got = try sa.unwrapSessionKeys(&update, wrapped, kl, &out);
                std.debug.print("ctgrind_result={x}\n", .{got.control_key});
                var bad = wrapped_buf;
                bad[9] ^= 1;
                const rej = if (sa.unwrapSessionKeys(&update, bad[0..wrapped.len], kl, &out)) |_| false else |_| true;
                std.debug.print("ctgrind_result={x}\n", .{[1]u8{@intFromBool(rej)}});
            }
        },
    }
}
