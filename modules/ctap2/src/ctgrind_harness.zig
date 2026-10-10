// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh ctap2`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-ctap2`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures (the client side of authenticatorClientPIN)
//!
//!  * `pin` — the PIN (8 bytes; its LENGTH is public) and the ECDH shared
//!    secret tainted: `validateNewPin`, `padPin`, `pinHash`, then the
//!    `newPinEnc`/`pinHashEnc` encryption and `pinUvAuthParam` MAC with
//!    `SharedSecret.encrypt`/`authenticate`, for protocols One and Two.
//!  * `token` — the shared secret tainted: `decryptToken` on an encrypted
//!    pinUvAuthToken (the ciphertext is the authenticator's wire response,
//!    marked defined) and `Token.authenticate`, both protocols.
//!
//! Until 2026-10-10 `validateNewPin` counted code points with
//! `std.unicode.utf8CountCodepoints`, which branched on the PIN bytes (1
//! context); `utf8CountCt` replaced it.
//!
//! The cryptography is `ctap2pin`'s; this module's own code is the PIN rules,
//! the padding and the plumbing.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const ctap2 = @import("root.zig");

const cp = ctap2.clientpin;
const Target = enum { pin, token };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var block: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &block, .{});
    var i: usize = 0;
    while (i < n) : (i += 32) {
        std.crypto.hash.sha2.Sha256.hash(&block, &block, .{});
        @memcpy(out[i..@min(n, i + 32)], block[0..@min(32, n - i)]);
    }
    return out;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

fn shared(protocol: ctap2.ctap2pin.Protocol, t: Taint) cp.SharedSecret {
    var ss: cp.SharedSecret = .{ .protocol = protocol, .platform_key = undefined };
    ss.bytes = secretBytes(64, "ctgrind-ctap2-shared-secret-v1");
    taintBytes(t, &ss.bytes);
    return ss;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var prng = std.Random.DefaultPrng.init(0xc7a2);
    const rng = prng.random();

    switch (target) {
        .pin => {
            var pin = "73a9f0c2".*;
            taintBytes(taint, &pin);
            // `validateNewPin` folds validity into ONE verdict and returns it
            // branch-free (a select), so the first branch on it is this
            // caller's `try`. The verdict is public (the user is told), so
            // it is marked defined here; nothing inside the module is.
            var verdict = cp.validateNewPin(&pin, 4);
            std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&verdict));
            try verdict;
            try cp.validateCurrentPin(&pin);
            const padded = cp.padPin(&pin);
            const ph = cp.pinHash(&pin);
            for ([_]ctap2.ctap2pin.Protocol{ .one, .two }) |proto| {
                const ss = shared(proto, taint);
                var enc: [64 + 16]u8 = undefined;
                const n = ss.encryptedLen(padded.len);
                try ss.encrypt(rng, enc[0..n], &padded);
                var hash_enc: [16 + 16]u8 = undefined;
                const hn = ss.encryptedLen(ph.len);
                try ss.encrypt(rng, hash_enc[0..hn], &ph);
                const mac = ss.authenticate(enc[0..n]);
                std.debug.print("ctgrind_result={x}\n", .{enc[0..n]});
                std.debug.print("ctgrind_result={x}\n", .{hash_enc[0..hn]});
                std.debug.print("ctgrind_result={x}\n", .{mac.slice()});
            }
        },
        .token => {
            for ([_]ctap2.ctap2pin.Protocol{ .one, .two }) |proto| {
                // The authenticator encrypts the token under the shared secret
                // (untainted copy); the client decrypts with a tainted one.
                const plain_tok = secretBytes(32, "ctgrind-ctap2-token-v1");
                const ss_auth = shared(proto, .no);
                var ct: [32 + 16]u8 = undefined;
                const n = ss_auth.encryptedLen(32);
                try ss_auth.encrypt(rng, ct[0..n], &plain_tok);
                const ss = shared(proto, taint);
                var tok = try ss.decryptToken(ct[0..n]);
                const sig = tok.authenticate("clientDataHash-and-rpIdHash....");
                std.debug.print("ctgrind_result={x}\n", .{tok.slice()});
                std.debug.print("ctgrind_result={x}\n", .{sig.slice()});
                tok.deinit();
            }
        },
    }
}
