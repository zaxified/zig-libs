// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the entry points burned in the
//! 2026-10-09 `check-secret-api` pass: `cipher.fullMac` / `verifyTruncatedMac`
//! and the outbound pickle codec (`encodeOutbound`, `decodeOutbound`,
//! `openOutbound`). The older `stackprobe_test.zig` (hand-made engine) is left
//! as it was. ReleaseFast only (`skipUnlessOptimized`, a runtime skip).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha512 = std.crypto.hash.sha2.Sha512;

const cipher = root.cipher;
const pickle = root.pickle;

// MAC and pickle codec: one HMAC / a few SHA-512-free copies, well under 64 KiB.
const P = sp.Probe(.{ .window = 64 * 1024 });

var hmac_key: [cipher.hmac_key_len]u8 = undefined;
var pickle_key: pickle.PickleKey = undefined;
var sess: root.OutboundSession = undefined;
var restored: root.OutboundSession = undefined;
var plain: [pickle.outbound_len]u8 = undefined;
var sealed: [pickle.sealed_outbound_len]u8 = undefined;
var mac: [cipher.full_mac_len]u8 = undefined;

fn label(comptime l: []const u8, out: []u8) void {
    var h: [64]u8 = undefined;
    Sha512.hash(l, &h, .{});
    @memcpy(out, h[0..out.len]);
}

test "STACKPROBE: megolm MAC and outbound pickle codec leave no key residue" {
    try sp.skipUnlessOptimized();
    label("megolm probe hmac key", &hmac_key);
    label("megolm probe pickle key", &pickle_key);
    var rdata: [128]u8 = undefined;
    label("megolm probe ratchet 0", rdata[0..64]);
    label("megolm probe ratchet 1", rdata[64..]);
    var seed: [32]u8 = undefined;
    label("megolm probe signing seed", &seed);
    root.Ratchet.init(&rdata, 7, &sess.ratchet);
    sess.signing_key = try Ed25519.KeyPair.generateDeterministic(seed);

    // Public input: derived from its own label, never from the key bytes.
    var data: [48]u8 = undefined;
    label("megolm probe message", &data);
    const keys = &[_][]const u8{&hmac_key};

    _ = try P.run("fullMac", cipher.fullMac, .{ &hmac_key, &data }, keys, .{});
    mac = cipher.fullMac(&hmac_key, &data);
    var tag: [8]u8 = mac[0..8].*;
    _ = try P.run("verifyTruncatedMac", cipher.verifyTruncatedMac, .{ &hmac_key, &data, &tag }, keys, .{});

    const sec = &[_][]const u8{ &sess.ratchet.data, &seed, &sess.signing_key.secret_key.bytes, &plain };
    _ = try P.run("encodeOutbound", pickle.encodeOutbound, .{ &sess, &plain }, sec, .{});
    _ = try P.run("decodeOutbound", pickle.decodeOutbound, .{ &plain, &restored }, &[_][]const u8{ &sess.ratchet.data, &seed, &sess.signing_key.secret_key.bytes, std.mem.asBytes(&restored) }, .{});

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    pickle.sealOutbound(io, &sess, &pickle_key, &sealed);
    _ = try P.run("openOutbound", pickle.openOutbound, .{ &sealed, &pickle_key, &restored }, &[_][]const u8{ &sess.ratchet.data, &seed, &pickle_key, std.mem.asBytes(&restored) }, .{});
    try std.testing.expectEqualSlices(u8, &sess.ratchet.data, &restored.ratchet.data);
}

// Added by the 2026-11-17 mutation audit: entry points the tests above and the
// older probe never measured on their own. `advanceStep` is public and burns;
// `InboundGroupSession.pickleSealed` is the inbound twin of the outbound one.
// (The `pickle.*` codec functions that are not burned themselves are left
// unprobed on purpose: a direct call leaves ratchet copies in its frames, the
// session wrappers' burns are what clear them; see SPEC "Audit 2026-11-17".)
var in_sess: root.InboundGroupSession = undefined;
var plain_in: [pickle.inbound_len]u8 = undefined;
var sealed_in: [pickle.sealed_inbound_len]u8 = undefined;

test "STACKPROBE: megolm advanceStep and the inbound sealed pickle leave no key residue" {
    try sp.skipUnlessOptimized();
    label("megolm probe pickle key", &pickle_key);
    var rdata: [128]u8 = undefined;
    label("megolm probe ratchet 0", rdata[0..64]);
    label("megolm probe ratchet 1", rdata[64..]);
    var seed: [32]u8 = undefined;
    label("megolm probe signing seed", &seed);
    root.Ratchet.init(&rdata, 7, &sess.ratchet);
    sess.signing_key = try Ed25519.KeyPair.generateDeterministic(seed);

    // advanceStep: the ratchet before and after one step are both secret.
    var r: root.Ratchet = undefined;
    root.Ratchet.init(&rdata, 7, &r);
    var next = r;
    next.advanceStep();
    const before = rdata;
    _ = try P.run("Ratchet.advanceStep", root.Ratchet.advanceStep, .{&r}, &[_][]const u8{ &before, &next.data }, .{});

    const exported: root.ExportedSessionKey = .{ .ratchet_index = 7, .ratchet = rdata, .signing_key = sess.signing_key.public_key.toBytes() };
    try root.InboundGroupSession.fromExportedKey(&exported, &in_sess);
    _ = in_sess.forgetBefore(9); // initial and latest ratchet differ from the pristine one
    const sec = &[_][]const u8{ &rdata, &in_sess.initial_ratchet.data, &in_sess.latest_ratchet.data, &pickle_key };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    _ = try P.run("InboundGroupSession.pickleSealed", root.InboundGroupSession.pickleSealed, .{ &in_sess, io, &pickle_key, &sealed_in }, sec, .{});
}
