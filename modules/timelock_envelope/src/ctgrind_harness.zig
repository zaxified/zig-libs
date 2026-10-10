// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh timelock_envelope`,
//! which builds every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-timelock_envelope`: memcheck's context count
//! is valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `kdf` — this module's own key derivation: `deriveKeys` and
//!    `stream.deriveStreamKey` with both lock secrets (`s_time`, `s_pq`)
//!    tainted. Suite id, round and transcript hash are public.
//!  * `env` — `Envelope128.seal` with the seal randomness (`s_time`, the
//!    tlock sigma, the HQC coins) and the plaintext tainted, then `open` of
//!    the (public, marked defined) envelope with the recipient's HQC
//!    decapsulation key tainted and the published round-1000 quicknet
//!    signature. The tlock and HQC internals carry their own rows (`tlock`,
//!    `hqc`); what this target adds is the composition.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const te = @import("root.zig");
const tlock = @import("tlock");
const hqc = @import("hqc");

const g1 = tlock.bls12_381.g1;
const g2 = tlock.bls12_381.g2;
const Env = te.Envelope128;
const Kem = hqc.Hqc128;
const Target = enum { kdf, env };
const Taint = enum { yes, no };

fn hexBytes(comptime n: usize, comptime hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// drand quicknet master public key and its round-1000 signature (the same
// pinned bytes `security_test.zig` and `tlock`'s KAT use).
const quicknet_pubkey_hex =
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183" ++
    "c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4b" ++
    "cb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece" ++
    "45a";
const round_1000_sig_hex =
    "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb112" ++
    "5e342b73a8dd2bacbe47e4b6b63ed5e39";

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

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .kdf => {
            var s_time = secretBytes(te.envelope.time_secret_bytes, "ctgrind-te-s-time-v1");
            var s_pq = secretBytes(hqc.params.shared_secret_bytes, "ctgrind-te-s-pq-v1");
            taintBytes(taint, &s_time);
            taintBytes(taint, &s_pq);
            var keys: te.DerivedKeys = undefined;
            te.deriveKeys(&keys, &s_time, &s_pq, Env.suite_id, 1000);
            var sk: [32]u8 = undefined;
            const th = secretBytes(32, "public transcript hash");
            te.stream.deriveStreamKey(&sk, &s_time, &s_pq, Env.suite_id, 1000, &th);
            std.debug.print("ctgrind_result={x}\n", .{keys.key ++ keys.nonce ++ sk});
        },
        .env => {
            var heap: [1 << 16]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&heap);
            const gpa = fba.allocator();
            var kp: Kem.KeyPair = undefined;
            Kem.keypair(&kp, &secretBytes(32, "ctgrind-te-hqc-seed-v1"));
            const p_pub = try g2.fromBytesCompressed(hexBytes(96, quicknet_pubkey_hex));
            const sig = try g1.fromBytesCompressed(hexBytes(48, round_1000_sig_hex));

            var rnd: Env.SealRandomness = .{
                .s_time = secretBytes(te.envelope.time_secret_bytes, "ctgrind-te-s-time-v1"),
                .tlock_sigma = secretBytes(te.envelope.time_secret_bytes, "ctgrind-te-sigma-v1"),
                .kem_coins = secretBytes(Kem.coins_bytes, "ctgrind-te-coins-v1"),
            };
            var pt = secretBytes(48, "ctgrind-te-plaintext-v1");
            taintBytes(taint, std.mem.asBytes(&rnd));
            taintBytes(taint, &pt);
            const env = try Env.seal(gpa, &pt, &kp.ek, p_pub, 1000, &rnd);
            std.debug.print("ctgrind_result={x}\n", .{env[0..64]});
            std.valgrind.memcheck.makeMemDefined(env); // the envelope is public

            taintBytes(taint, std.mem.asBytes(&kp.dk));
            const opened = try Env.open(gpa, env, &kp.dk, sig);
            std.debug.print("ctgrind_result={x}\n", .{opened});
        },
    }
}
