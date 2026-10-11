// SPDX-License-Identifier: MIT

//! Dead-stack probe for every key-touching entry point of `secure.zig`
//! (`testkit.stackprobe`): residue below each burn, and the signing /
//! encryption keys and the derivation master as needles in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).

const std = @import("std");
const secure = @import("secure.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var master: [32]u8 = undefined;
var key: secure.Key = undefined;
var out: [512]u8 = undefined;
var plain: [512]u8 = undefined;

test "STACKPROBE: no key residue after any secure.zig entry point" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("cookies probe master", &master, .{});
    try secure.Key.deriveInto(&key, &master);
    const keys = [_]secure.Key{key};
    const k = &[_][]const u8{ &key.signing, &key.encryption };
    const value = "user=42&role=admin";

    var signed_buf: [128]u8 = undefined;
    const s = try secure.signed.sign(&key, "sid", value, &signed_buf, .{});
    var sealed_buf: [128]u8 = undefined;
    const sealed = try secure.private.seal(&key, "sid", value, @splat(9), &sealed_buf);

    var derived: secure.Key = undefined;
    _ = try P.run("Key.deriveInto", secure.Key.deriveInto, .{ &derived, @as([]const u8, &master) }, &.{ &master, &key.signing, &key.encryption }, .{});
    _ = try P.run("signed.sign", secure.signed.sign, .{ &key, "sid", value, &out, secure.signed.Options{} }, k, .{});
    _ = try P.run("signed.verify", secure.signed.verify, .{ @as([]const secure.Key, &keys), "sid", s, secure.signed.Options{} }, k, .{});
    _ = try P.run("private.seal", secure.private.seal, .{ &key, "sid", value, @as([12]u8, @splat(9)), &out }, k, .{});
    _ = try P.run("private.open", secure.private.open, .{ @as([]const secure.Key, &keys), "sid", sealed, &plain }, k, .{});
}
