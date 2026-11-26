// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `serializePrivSlip132` and
//! `parseSlip132`, the SLIP-132 forms of the extended-private-key codec that
//! `stackprobe_test.zig` does not call: residue below each burn; the private
//! key and chain code as needles. ReleaseFast/ReleaseSmall only. Coverage
//! sweep 2026-11-26.

const std = @import("std");
const bip32 = @import("bip32.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var master: bip32.ExtendedPrivKey = undefined;
var text: [128]u8 = undefined;
var text_len: usize = 0;
var parsed: bip32.ParsedKey = undefined;

fn parseW(o: *bip32.ParsedKey) !void {
    _ = try bip32.parseSlip132(text[0..text_len], o);
}

test "STACKPROBE: serializePrivSlip132 / parseSlip132 leave no private key or chain code on the dead stack" {
    try sp.skipUnlessOptimized();
    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("bip32 probe2 seed", &seed, .{});
    try bip32.masterFromSeed(&seed, &master);
    defer master.deinit();
    const ks = [_][]const u8{ &master.privkey, &master.chain_code };
    _ = try P.run("serializePrivSlip132", bip32.serializePrivSlip132, .{ &master, bip32.Network.mainnet, bip32.Slip132Script.p2wpkh, @as([]u8, &text) }, &ks, .{});
    text_len = (try bip32.serializePrivSlip132(&master, .mainnet, .p2wpkh, &text)).len;
    _ = try P.run("parseSlip132", parseW, .{&parsed}, &ks, .{});
}
