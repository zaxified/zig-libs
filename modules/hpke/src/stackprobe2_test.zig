// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `suite.labeledExtract` and
//! `suite.labeledExpand`, burned (the KEM / key-schedule entry
//! points are in `stackprobe_test.zig`). Per-derivation calls: tight burn
//! (`kdf_burn`). ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const suite = @import("suite.zig");
const sp = @import("testkit").stackprobe;

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const P = sp.Probe(.{ .window = 32 * 1024 });

var ikm: [32]u8 = undefined;
var prk: [Hkdf.prk_length]u8 = undefined;
var okm: [32]u8 = undefined;
const sid = "HPKE\x00\x20\x00\x01\x00\x01";

fn extract(out: *[Hkdf.prk_length]u8, i: *const [32]u8) void {
    suite.labeledExtract(Hkdf, out, sid, "", "secret", i);
}

fn expand(out: *[32]u8, p: *const [Hkdf.prk_length]u8) !void {
    try suite.labeledExpand(Hkdf, sid, p, "key", "info", out);
}

test "STACKPROBE: labeledExtract and labeledExpand leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("hpke probe2 ikm", &ikm, .{});
    _ = try P.run("labeledExtract", extract, .{ &prk, &ikm }, &.{ &ikm, &prk }, .{});
    _ = try P.run("labeledExpand", expand, .{ &okm, &prk }, &.{ &prk, &okm }, .{});
}

const root = @import("root.zig");
var pq_ikm: [32]u8 = undefined;
var mk_ref: root.MlKem768Kem.KeyPair = undefined;
var mk_out: root.MlKem768Kem.KeyPair = undefined;
var hy_ref: root.MlKem768X25519Kem.KeyPair = undefined;
var hy_out: root.MlKem768X25519Kem.KeyPair = undefined;

fn mkDerive(out: *root.MlKem768Kem.KeyPair, i: *const [32]u8) void {
    root.MlKem768Kem.deriveKeyPair(out, i);
}
fn hyDerive(out: *root.MlKem768X25519Kem.KeyPair, i: *const [32]u8) void {
    root.MlKem768X25519Kem.deriveKeyPair(out, i);
}

test "STACKPROBE: the PQ and hybrid KEMs' deriveKeyPair leave no ikm or seed on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("hpke probe2 pq ikm", &pq_ikm, .{});
    root.MlKem768Kem.deriveKeyPair(&mk_ref, &pq_ikm);
    _ = try P.run("MlKem768Kem.deriveKeyPair", mkDerive, .{ &mk_out, &pq_ikm }, &.{ &pq_ikm, &mk_ref.seed }, .{});
    root.MlKem768X25519Kem.deriveKeyPair(&hy_ref, &pq_ikm);
    _ = try P.run("MlKem768X25519Kem.deriveKeyPair", hyDerive, .{ &hy_out, &pq_ikm }, &.{ &pq_ikm, &hy_ref.seed, &hy_ref.t_secret }, .{});
}
