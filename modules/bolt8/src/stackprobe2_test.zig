// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for the key
//! and transport entry points added to the dead-stack rule in the 2026-10-09
//! sweep: `KeyPair.generateDeterministic`, `KeyPair.generate`, `dh`,
//! `Direction.init`. (`Initiator`/`Responder.init`, the acts and
//! `Transport.init` stay covered by the older `stackprobe_test.zig`.)
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip).

const std = @import("std");
const root = @import("root.zig");
const kv = @import("kat_vectors.zig");
const sp = @import("testkit").stackprobe;

const dh = root.dh;
const transport = root.transport;

// Window above the deepest burn (32 KiB one-shot ECC).
const P = sp.Probe(.{ .window = 64 * 1024 });

var kp_out: dh.KeyPair = undefined;
var shared_out: [32]u8 = undefined;
var prng: std.Random.DefaultPrng = undefined;
var dir_out: transport.Direction = undefined;
var chain: [32]u8 = @splat(0x5c);
var tx_out: transport.Transport = undefined;
var result: root.HandshakeResult = undefined;

test "STACKPROBE: bolt8 key creation, ECDH and direction init leave no secret in any frame" {
    try sp.skipUnlessOptimized();

    _ = try P.run("KeyPair.generateDeterministicInto", dh.KeyPair.generateDeterministicInto, .{ &kp_out, kv.init_ls_priv }, &[_][]const u8{ kv.init_ls_priv, &kp_out.secret_key }, .{});

    prng = std.Random.DefaultPrng.init(0xb018_0003);
    _ = try P.run("KeyPair.generate", dh.KeyPair.generate, .{ &kp_out, prng.random() }, &[_][]const u8{&kp_out.secret_key}, .{});

    // `dh` returns the 32-byte digest by value (it is the act's mixKey input,
    // consumed inside the burned act); the secret key is the needle here.
    const r = try P.run("dh", dh.dh, .{ kv.init_e_priv, kv.resp_ls_pub.* }, &[_][]const u8{kv.init_e_priv}, .{});
    _ = r;

    // One-shot per connection (4 KiB burn).
    _ = try P.run("Direction.init", transport.Direction.init, .{ &dir_out, kv.msg_test_sk, &chain }, &[_][]const u8{ kv.msg_test_sk, &dir_out.cipher.k }, .{});

    result = .{ .sk = kv.msg_test_sk.*, .rk = kv.msg_test_rk.*, .ck = kv.msg_test_ck.*, .handshake_hash = @splat(0), .remote_static = @splat(0) };
    _ = try P.run("Transport.init", transport.Transport.init, .{ &tx_out, &result }, &[_][]const u8{ &result.sk, &result.rk, &tx_out.tx.cipher.k, &tx_out.rx.cipher.k }, .{});
}
