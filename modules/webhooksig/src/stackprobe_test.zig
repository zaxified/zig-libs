// SPDX-License-Identifier: MIT

//! Dead-stack probe for every secret-touching entry point (`testkit.stackprobe`):
//! residue below each burn, and the HMAC key / Ed25519 secret as needles in
//! any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the
//! body is type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const Ed25519 = std.crypto.sign.Ed25519;

const P = sp.Probe(.{ .window = 64 * 1024 });

const body = "{\"event\":\"dead-stack probe\"}";
const msg_id = "msg_probe";
const ts: u64 = 1_760_000_000;

var key: [32]u8 = undefined;
var out: [256]u8 = undefined;
var scratch: [256]u8 = undefined;
var kp: Ed25519.KeyPair = undefined;
var kp_text: [6 + 44]u8 = undefined;

fn setup() void {
    std.crypto.hash.sha2.Sha256.hash("webhooksig probe key", &key, .{});
    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("webhooksig probe seed", &seed, .{});
    kp = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    @memcpy(kp_text[0..5], "whsk_");
    _ = std.base64.standard.Encoder.encode(kp_text[5..49], &seed);
    kp_text[49] = ' ';
}

test "STACKPROBE: no HMAC key or Ed25519 secret residue after any entry point" {
    try sp.skipUnlessOptimized();
    setup();
    const secret: []const u8 = &key;
    const k = &[_][]const u8{&key};
    const secrets = [_][]const u8{secret};

    // Presented values: the real signature, so verify runs to the end.
    var good: [root.signature_hex_len + 7]u8 = undefined;
    _ = try root.sign(secret, body, &good);
    var std_sig: [root.standard.v1_len]u8 = undefined;
    _ = try root.standard.sign(&std_sig, secret, msg_id, ts, body);
    var stripe_sig: [96]u8 = undefined;
    const stripe_v = try root.stripe.sign(&stripe_sig, secret, ts, body);
    var slack_sig: [root.slack.signature_len]u8 = undefined;
    _ = try root.slack.sign(&slack_sig, secret, ts, body);
    var tsb: [20]u8 = undefined;
    const ts_text = try std.fmt.bufPrint(&tsb, "{d}", .{ts});

    _ = try P.run("computeHex", root.computeHex, .{ secret, body }, k, .{});
    _ = try P.run("sign", root.sign, .{ secret, body, &out }, k, .{});
    _ = try P.run("verify", root.verify, .{ secret, body, &good }, k, .{});
    _ = try P.run("signFormat sha512 b64", root.signFormat, .{ .{ .prefix = "", .digest = .sha512, .encoding = .base64 }, secret, body, &out }, k, .{});
    _ = try P.run("standard.sign", root.standard.sign, .{ &out, secret, msg_id, ts, body }, k, .{});
    _ = try P.run("standard.verify", root.standard.verify, .{ .{ .secrets = &secrets }, msg_id, ts_text, &std_sig, body, @as(i64, @intCast(ts)), 300 }, k, .{});
    _ = try P.run("stripe.sign", root.stripe.sign, .{ &out, secret, ts, body }, k, .{});
    _ = try P.run("stripe.verify", root.stripe.verify, .{ &secrets, stripe_v, body, @as(i64, @intCast(ts)), 300 }, k, .{});
    _ = try P.run("slack.sign", root.slack.sign, .{ &out, secret, ts, body }, k, .{});
    _ = try P.run("slack.verify", root.slack.verify, .{ &secrets, ts_text, &slack_sig, body, @as(i64, @intCast(ts)), 300 }, k, .{});

    var v = try root.Verifier.init(std.testing.allocator, .{ .secret = secret });
    defer v.deinit();
    _ = try P.run("Verifier.verifyBody", root.Verifier.verifyBody, .{ &v, body, &good }, k, .{});

    const ed = &[_][]const u8{ &kp.secret_key.bytes, std.mem.asBytes(&kp) };
    _ = try P.run("standard.signEd25519", root.standard.signEd25519, .{ &out, &scratch, &kp, msg_id, ts, body }, ed, .{});
    var decoded: Ed25519.KeyPair = undefined;
    _ = try P.run("standard.decodeSigningKey", root.standard.decodeSigningKey, .{ &decoded, kp_text[0..49] }, &.{ std.mem.asBytes(&decoded), &kp.secret_key.bytes }, .{});
    try std.testing.expectEqualSlices(u8, &kp.secret_key.bytes, &decoded.secret_key.bytes);
}
