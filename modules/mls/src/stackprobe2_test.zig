// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the public key-schedule, tag,
//! derivation and signing helpers `stackprobe_test.zig` (which drives whole
//! `Group` operations) never calls on their own: `ExpandWithLabelScratch`,
//! `DeriveTreeSecret`, `SignWithLabel`, `joinerSecret`, `welcomeSecret`,
//! `epochSecret`, `deriveEpochFromJoiner`, `confirmationTag` /
//! `verifyConfirmationTag`, `membershipTag` / `verifyMembershipTag`,
//! `secrettree.childSecret`, `welcome.encryptGroupInfo` /
//! `decryptGroupInfo`, `CipherSuite.signatureKeyPair`, and the Ed448
//! suite's `KeyPair.generateDeterministicInto` / `sign`. Residue below each
//! burn; the secret inputs and outputs as needles. ReleaseFast/ReleaseSmall
//! only. Coverage sweep 2026-11-26.

const std = @import("std");
const mls = @import("root.zig");
const sp = @import("testkit").stackprobe;

const S = mls.suite.default;
const crypto = mls.crypto;
const ks = mls.keyschedule;
const gpa = std.heap.page_allocator; // global-alloc-ok: heap buffers are not on the stack under measurement; page_allocator keeps the probe's allocations out of the leak check's bookkeeping frames

const P = sp.Probe(.{ .window = 256 * 1024 });

var a: [S.Nh]u8 = undefined;
var b: [S.Nh]u8 = undefined;
var out: [S.Nh]u8 = undefined;
var out_long: [64]u8 = undefined;
var scratch: [512]u8 = undefined;
var tag: [S.Nm]u8 = undefined;
var epoch: ks.EpochSecrets(S) = undefined;
var sig_kp: S.Sig.KeyPair = undefined;
var priv: [S.Nssk]u8 = undefined;
var seed448: [mls.suite.Ed448.KeyPair.seed_length]u8 = undefined;
var kp448: mls.suite.Ed448.KeyPair = undefined;
const gc = "mls probe2 group context";

fn expandW(s: *const [S.Nh]u8, o: []u8, sc: []u8) !void {
    return crypto.ExpandWithLabelScratch(S, s, "probe", "ctx", o, sc);
}
fn treeW(s: *const [S.Nh]u8, o: []u8) !void {
    return crypto.DeriveTreeSecret(S, s, "key", 7, o);
}
fn signW(kp: *const S.Sig.KeyPair) !S.Sig.Signature {
    return crypto.SignWithLabel(S, kp, "LeafNodeTBS", "probe content");
}
fn joinerW(x: *const [S.Nh]u8, y: *const [S.Nh]u8, o: *[S.Nh]u8) !void {
    return ks.joinerSecret(S, gpa, x, y, gc, o);
}
fn welcomeW(x: *const [S.Nh]u8, y: *const [S.Nh]u8, o: *[S.Nh]u8) !void {
    return ks.welcomeSecret(S, x, y, o);
}
fn epochW(x: *const [S.Nh]u8, y: *const [S.Nh]u8, o: *[S.Nh]u8) !void {
    return ks.epochSecret(S, gpa, x, y, gc, o);
}
fn deriveEpochW(x: *const [S.Nh]u8, y: *const [S.Nh]u8, o: *ks.EpochSecrets(S)) !void {
    return ks.deriveEpochFromJoiner(S, gpa, x, y, gc, o);
}
fn confTagW(k: *const [S.Nh]u8) [S.Nm]u8 {
    return ks.confirmationTag(S, k, "transcript");
}
fn verConfTagW(k: *const [S.Nh]u8) !void {
    return ks.verifyConfirmationTag(S, k, "transcript", &tag);
}
fn memTagW(k: *const [S.Nh]u8) [S.Nm]u8 {
    return ks.membershipTag(S, k, "tbm");
}
fn verMemTagW(k: *const [S.Nh]u8) !void {
    return ks.verifyMembershipTag(S, k, "tbm", &tag);
}
fn childW(p: *const [S.Nh]u8, o: *[S.Nh]u8) !void {
    return mls.secrettree.childSecret(S, p, true, o);
}
var egi: []u8 = &.{};
fn encGiW(w: *const [S.Nh]u8) !void {
    const r = try mls.welcome.encryptGroupInfo(S, gpa, w, "probe group info");
    gpa.free(r);
}
fn decGiW(w: *const [S.Nh]u8) !void {
    const r = try mls.welcome.decryptGroupInfo(S, gpa, w, egi);
    gpa.free(r);
}
fn sigKpW(p: *const [S.Nssk]u8, o: *S.Sig.KeyPair) !void {
    return S.signatureKeyPair(p, o);
}
fn signAllocW(kp: *const S.Sig.KeyPair) !S.Sig.Signature {
    return crypto.SignWithLabelAlloc(S, gpa, kp, "LeafNodeTBS", "probe content (alloc)");
}
var kem_r: S.Kem.KeyPair = undefined;
var kem_e: S.Kem.KeyPair = undefined;
var enc: S.Kem.EncappedKey = undefined;
var pt: [48]u8 = undefined;
var ct: [48 + 16]u8 = undefined;
var dec: [48]u8 = undefined;
var ei: ks.ExternalInit(S) = undefined;
fn decScratchW(kp: *const S.Kem.KeyPair) !void {
    return crypto.DecryptWithLabelScratch(S, enc, kp, "probe label", "probe ctx", &ct, &dec, &scratch);
}
fn extDetW(eph: *const S.Kem.KeyPair) !void {
    return ks.externalInitSenderDeterministic(S, kem_r.public_key, eph, &ei);
}
fn sign448W(kp: *const mls.suite.Ed448.KeyPair) !mls.suite.Ed448.Signature {
    return kp.sign("probe content", null);
}

test "STACKPROBE: mls key-schedule, tag, tree-derivation and signing helpers leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("mls probe2 a", &a, .{});
    std.crypto.hash.sha2.Sha256.hash("mls probe2 b", &b, .{});
    std.crypto.hash.sha2.Sha256.hash("mls probe2 priv", priv[0..32], .{});
    var h: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("mls probe2 ed448 seed", &h, .{});
    @memcpy(seed448[0..57], h[0..57]);
    try S.signatureKeyPair(&priv, &sig_kp);
    const sig_secret = std.mem.asBytes(&sig_kp.secret_key);

    _ = try P.run("ExpandWithLabelScratch", expandW, .{ &a, @as([]u8, &out_long), @as([]u8, &scratch) }, &.{ &a, &out_long }, .{});
    _ = try P.run("DeriveTreeSecret", treeW, .{ &a, @as([]u8, &out) }, &.{ &a, &out }, .{});
    _ = try P.run("SignWithLabel", signW, .{&sig_kp}, &.{ &priv, sig_secret }, .{});
    _ = try P.run("joinerSecret", joinerW, .{ &a, &b, &out }, &.{ &a, &b, &out }, .{});
    _ = try P.run("welcomeSecret", welcomeW, .{ &a, &b, &out }, &.{ &a, &b, &out }, .{});
    _ = try P.run("epochSecret", epochW, .{ &a, &b, &out }, &.{ &a, &b, &out }, .{});
    _ = try P.run("deriveEpochFromJoiner", deriveEpochW, .{ &a, &b, &epoch }, &.{ &a, &b, std.mem.asBytes(&epoch) }, .{});
    // A by-value tag lands in the probe's call frame by shape: the key is the needle.
    _ = try P.run("confirmationTag", confTagW, .{&a}, &.{&a}, .{});
    tag = ks.confirmationTag(S, &a, "transcript");
    _ = try P.run("verifyConfirmationTag", verConfTagW, .{&a}, &.{&a}, .{});
    _ = try P.run("membershipTag", memTagW, .{&a}, &.{&a}, .{});
    tag = ks.membershipTag(S, &a, "tbm");
    _ = try P.run("verifyMembershipTag", verMemTagW, .{&a}, &.{&a}, .{});
    _ = try P.run("secrettree.childSecret", childW, .{ &a, &out }, &.{ &a, &out }, .{});
    _ = try P.run("welcome.encryptGroupInfo", encGiW, .{&a}, &.{&a}, .{});
    egi = try mls.welcome.encryptGroupInfo(S, gpa, &a, "probe group info");
    defer gpa.free(egi);
    _ = try P.run("welcome.decryptGroupInfo", decGiW, .{&a}, &.{&a}, .{});
    _ = try P.run("CipherSuite.signatureKeyPair", sigKpW, .{ &priv, &sig_kp }, &.{ &priv, sig_secret }, .{});
    _ = try P.run("Ed448.KeyPair.generateDeterministicInto", mls.suite.Ed448.KeyPair.generateDeterministicInto, .{ &kp448, &seed448 }, &.{&seed448}, .{});
    _ = try P.run("Ed448.KeyPair.sign", sign448W, .{&kp448}, &.{&seed448}, .{});

    // Twins of probed blocks (2026-11-27 coverage sweep).
    _ = try P.run("SignWithLabelAlloc", signAllocW, .{&sig_kp}, &.{ &priv, sig_secret }, .{});
    kem_r = S.Kem.KeyPair.generateDeterministic(a);
    kem_e = S.Kem.KeyPair.generateDeterministic(b);
    std.crypto.hash.sha2.Sha256.hash("mls probe2 pt", pt[0..32], .{});
    @memcpy(pt[32..], pt[0..16]);
    var th: std.Io.Threaded = .init(gpa, .{});
    defer th.deinit();
    enc = try crypto.EncryptWithLabel(S, kem_r.public_key, th.io(), "probe label", "probe ctx", &pt, &ct);
    _ = try P.run("DecryptWithLabelScratch", decScratchW, .{&kem_r}, &.{ &kem_r.secret_key, &pt }, .{});
    try std.testing.expectEqualSlices(u8, &pt, &dec);
    try ks.externalInitSenderDeterministic(S, kem_r.public_key, &kem_e, &ei);
    const init_secret = ei.init_secret;
    _ = try P.run("externalInitSenderDeterministic", extDetW, .{&kem_e}, &.{ &kem_e.secret_key, &init_secret }, .{});
}
