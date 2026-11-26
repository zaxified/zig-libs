// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the handshake constructors
//! `stackprobe_test.zig` does not call by name: the `*Ephemeral`, `initPsk`
//! and `initPskEphemeral` forms of `Initiator` / `Responder` and the XX
//! roles' `initEphemeral`. Residue below each burn; needles: the static and
//! ephemeral secret keys and the PSK. ReleaseFast/ReleaseSmall only.
//! Coverage sweep 2026-11-26.

const std = @import("std");
const tk = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 256 * 1024 });
const ctx: tk.FabricContext = .{ .isid = 0x123456, .initiator_pe = 11, .responder_pe = 22 };

var s_i: tk.KeyPair = undefined;
var s_r: tk.KeyPair = undefined;
var e: tk.KeyPair = undefined;
var psk: [32]u8 = undefined;
var ini: tk.Initiator = undefined;
var rsp: tk.Responder = undefined;
var xini: tk.XxInitiator = undefined;
var xrsp: tk.XxResponder = undefined;

fn seed(comptime label: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("tenantkex-probe2/" ++ label, &out, .{});
    return out;
}

test "STACKPROBE: the ephemeral / PSK handshake constructors leave no static, ephemeral or PSK secret on the dead stack" {
    try sp.skipUnlessOptimized();
    s_i = tk.KeyPair.generateDeterministic(seed("s_i"));
    s_r = tk.KeyPair.generateDeterministic(seed("s_r"));
    e = tk.KeyPair.generateDeterministic(seed("e"));
    psk = seed("psk");
    const ks = [_][]const u8{ &s_i.secret_key, &s_r.secret_key, &e.secret_key, &psk };

    _ = try P.run("Initiator.initEphemeral", tk.Initiator.initEphemeral, .{ &ini, &s_i, s_r.public_key, ctx, &e }, &ks, .{});
    ini.wipe();
    _ = try P.run("Initiator.initPsk", tk.Initiator.initPsk, .{ &ini, &s_i, s_r.public_key, ctx, &psk }, &ks, .{});
    ini.wipe();
    _ = try P.run("Initiator.initPskEphemeral", tk.Initiator.initPskEphemeral, .{ &ini, &s_i, s_r.public_key, ctx, &psk, &e }, &ks, .{});
    ini.wipe();
    _ = try P.run("Responder.initEphemeral", tk.Responder.initEphemeral, .{ &rsp, &s_r, s_i.public_key, ctx, &e }, &ks, .{});
    rsp.wipe();
    _ = try P.run("Responder.initPsk", tk.Responder.initPsk, .{ &rsp, &s_r, s_i.public_key, ctx, &psk }, &ks, .{});
    rsp.wipe();
    _ = try P.run("Responder.initPskEphemeral", tk.Responder.initPskEphemeral, .{ &rsp, &s_r, s_i.public_key, ctx, &psk, &e }, &ks, .{});
    rsp.wipe();
    _ = try P.run("XxInitiator.initEphemeral", tk.XxInitiator.initEphemeral, .{ &xini, &s_i, ctx, &e }, &ks, .{});
    _ = try P.run("XxResponder.initEphemeral", tk.XxResponder.initEphemeral, .{ &xrsp, &s_r, s_i.public_key, ctx, &e }, &ks, .{});
}
