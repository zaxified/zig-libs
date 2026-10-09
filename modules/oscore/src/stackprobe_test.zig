// SPDX-License-Identifier: MIT

//! Dead-stack probe for the key-derivation entry points (`testkit.stackprobe`):
//! residue below each burn, and the master secret / derived key as needles in
//! any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the
//! body is type-checked in every mode). `deriveContext` returns the context
//! (with both keys) by value -- the caller owns that result by design -- so
//! only the master secret is a needle for it.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var master: [32]u8 = undefined;
var out_key: [root.key_length]u8 = undefined;
var out_iv: [root.nonce_length]u8 = undefined;
const salt = "9e7ca92223786340";
const sender_id: []const u8 = &.{0x01};
const recipient_id: []const u8 = &.{};

test "STACKPROBE: no OSCORE master secret or derived key residue" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("oscore probe secret", &master, .{});
    const gpa = std.heap.page_allocator;
    const ms = &[_][]const u8{&master};

    _ = try P.run("deriveKey sender key", root.deriveKey, .{ gpa, &master, salt, sender_id, null, .aes_ccm_16_64_128, .key, &out_key }, &.{ &master, &out_key }, .{});
    _ = try P.run("deriveKey common iv", root.deriveKey, .{ gpa, &master, salt, &.{}, null, .aes_ccm_16_64_128, .iv, &out_iv }, &.{ &master, &out_iv }, .{});
    _ = try P.run("deriveContext", root.deriveContext, .{ gpa, &master, salt, null, sender_id, recipient_id, .aes_ccm_16_64_128 }, ms, .{});
}
