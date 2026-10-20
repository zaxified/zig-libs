// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh minisign`, which builds
//! the harness and prints the control table.
//!
//! Not wired into `zig build test-minisign`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The two secrets minisign holds: the Ed25519 signing seed and the secret-key
//! password. Each is tainted in place and the public API is driven.
//!
//!  * `sign` — a key pair from a fixed seed, the seed (the first 32 bytes of
//!    std's 64-byte secret key; the rest is the public key) tainted: `signDigest`
//!    over a BLAKE2b-512 digest of a public message and `signTrustedComment`.
//!    The Ed25519 arithmetic is std's.
//!  * `seal` — the same tainted key pair plus a tainted password through
//!    `sealSecretKey` (scrypt at a deliberately tiny cost, so valgrind finishes;
//!    the cost is public and changes no code path). The sealed struct is public.
//!  * `open` — a key sealed with known parameters, opened with a tainted
//!    password: scrypt, the keystream XOR, the BLAKE2b-256 checksum and its
//!    `timing_safe.eql` against the stored one, whose bool verdict
//!    (`WrongPassword` or not) is the one branch the module takes on a tainted
//!    value — public by design: the caller learns accept/reject. The recovered
//!    key then goes through std's `Ed25519.KeyPair.fromSecretKey`.
//!
//! Every output (signature, sealed key) is marked defined right after it is
//! produced: it is public, and the later printing must not show up as noise.
//! The propagation witness is printed BEFORE that declassification: a tainted
//! copy goes through `std.debug.print`, which is not constant-time, so the
//! total is non-zero while the in-file count stays what the module does.

const std = @import("std");
const builtin = @import("builtin");
const minisign = @import("root.zig");

const memcheck = std.valgrind.memcheck;

const Target = enum { sign, seal, open };
const Taint = enum { yes, no };

const seed: [32]u8 = @splat(7);
const password = "correct horse battery staple";
const salt: [minisign.salt_length]u8 = @splat(3);
// scrypt at N = 2^4, r = 8: the smallest cost `fromLimits` accepts quickly.
const ops_limit: u64 = 1 << 15;
const mem_limit: usize = 1 << 14;

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) memcheck.makeMemUndefined(bytes);
}

fn publish(label: []const u8, bytes: []u8) void {
    var copy: [256]u8 = undefined;
    const n = @min(bytes.len, copy.len);
    @memcpy(copy[0..n], bytes[0..n]);
    std.debug.print("ctgrind_result {s}={x}\n", .{ label, copy[0..n] });
    memcheck.makeMemDefined(bytes);
}

fn keyPair(t: Taint) !minisign.KeyPair {
    var kp: minisign.KeyPair = .{
        .key_number = @splat(9),
        .ed25519 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed),
    };
    taint(t, kp.ed25519.secret_key.bytes[0..32]);
    return kp;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const t = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var buf: [1 << 20]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const gpa = fba.allocator();

    switch (target) {
        .sign => {
            var kp = try keyPair(t);
            defer kp.wipe();
            var digest: [minisign.prehash_length]u8 = undefined;
            var h = minisign.Blake2b512.init();
            h.update("a public file");
            h.final(&digest);
            var sig = try minisign.signDigest(&kp, digest);
            publish("signature", std.mem.asBytes(&sig.signature));
            var global = try minisign.signTrustedComment(gpa, &kp, sig, "timestamp:1700000000");
            publish("global_signature", &global);
        },
        .seal => {
            var kp = try keyPair(t);
            defer kp.wipe();
            var pw = password.*;
            taint(t, &pw);
            var sealed: minisign.RawSecretKey = std.mem.zeroes(minisign.RawSecretKey);
            try minisign.sealSecretKey(gpa, &sealed, &kp, &pw, salt, ops_limit, mem_limit);
            publish("sealed", std.mem.asBytes(&sealed));
        },
        .open => {
            var kp = try keyPair(.no);
            defer kp.wipe();
            var sealed: minisign.RawSecretKey = std.mem.zeroes(minisign.RawSecretKey);
            try minisign.sealSecretKey(gpa, &sealed, &kp, password, salt, ops_limit, mem_limit);
            fba.reset();
            var pw = password.*;
            taint(t, &pw);
            var opened: minisign.KeyPair = undefined;
            const ok = if (minisign.openSecretKey(gpa, &opened, &sealed, &pw)) |_| true else |_| false;
            std.debug.print("ctgrind_result open={}\n", .{ok});
            if (ok) {
                // The recovered key's public half: a value derived from the
                // decrypted secret, for the output pin.
                var pk = opened.ed25519.public_key.toBytes();
                publish("opened_public_key", &pk);
                opened.wipe();
            }
        },
    }
}
