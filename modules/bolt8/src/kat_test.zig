// SPDX-License-Identifier: MIT

//! Full-handshake KAT assertions against BOLT#8 Appendix A: the complete
//! act1->act2->act3 walk (both sides, byte-exact against the published
//! wire messages and transport keys), all five crypto-level negative
//! vectors (bad MACs at each act + the decryptable-but-unparseable `rs`),
//! and a post-handshake transport round-trip over the derived keys.
//! Framing round-trips, the DH primitive, `init()`'s pre-Act-One
//! transcript, and transport framing + key rotation are additionally
//! exercised standalone in `dh.zig`/`act.zig`/`handshake.zig`/
//! `transport.zig`'s own test blocks.

const std = @import("std");
const testing = std.testing;
const kv = @import("kat_vectors.zig");
const dh = @import("dh.zig");
const act = @import("act.zig");
const handshake = @import("handshake.zig");
const transport = @import("transport.zig");

/// An initiator that has emitted Act One with the KAT-injected ephemeral —
/// the state every "initiator receives Act Two" test starts from.
fn initiatorAfterAct1() !handshake.Initiator {
    const ls = try dh.KeyPair.generateDeterministic(kv.init_ls_priv.*);
    var initiator = handshake.Initiator.init(ls, kv.resp_ls_pub.*);
    initiator.e = try dh.KeyPair.generateDeterministic(kv.init_e_priv.*);
    // `undefined` random: `e` is pre-set (Appendix A's own KAT hook), so
    // genAct1 never draws randomness.
    const a1 = try initiator.genAct1(undefined);
    try testing.expectEqualSlices(u8, kv.act1_bytes, &a1.toBytes());
    return initiator;
}

/// A responder that has consumed the published Act One and emitted Act Two
/// with the KAT-injected ephemeral — the state every "responder receives
/// Act Three" test starts from.
fn responderAfterAct2() !handshake.Responder {
    const ls = try dh.KeyPair.generateDeterministic(kv.resp_ls_priv.*);
    var responder = handshake.Responder.init(ls);
    try responder.readAct1(try act.Act1.fromBytes(kv.act1_bytes));
    responder.e = try dh.KeyPair.generateDeterministic(kv.resp_e_priv.*);
    const a2 = try responder.genAct2(undefined);
    try testing.expectEqualSlices(u8, kv.act2_bytes, &a2.toBytes());
    return responder;
}

test "KAT: full 'transport-initiator successful handshake' — act1/act2/act3 + sk/rk, end-to-end" {
    // Act One (initiator emits, byte-exact) + Act Two (responder consumes
    // Act One and emits, byte-exact) — asserted inside the helpers.
    var initiator = try initiatorAfterAct1();
    var responder = try responderAfterAct2();

    // Act Two, initiator side: consume the published bytes.
    try initiator.readAct2(try act.Act2.fromBytes(kv.act2_bytes));
    try testing.expectEqual(kv.resp_e_pub.*, initiator.re_pub.?);

    // Act Three, initiator side: byte-exact wire message + published
    // transport keys (sk/rk from the INITIATOR's perspective) + the
    // post-split ck that seeds the rotation ratchet.
    const a3 = try initiator.genAct3();
    try testing.expectEqualSlices(u8, kv.act3_bytes, &a3.msg.toBytes());
    try testing.expectEqual(kv.init_sk.*, a3.result.sk);
    try testing.expectEqual(kv.init_rk.*, a3.result.rk);
    try testing.expectEqual(kv.ck_temp_k3[0].*, a3.result.ck);

    // Act Three, responder side: same keys with sk/rk SWAPPED (the
    // responder's `rk` receives what the initiator's `sk` sends), same
    // ck, same final handshake hash, and the initiator's static key
    // correctly recovered from the encrypted `c` field.
    const r = try responder.readAct3(try act.Act3.fromBytes(kv.act3_bytes));
    try testing.expectEqual(a3.result.sk, r.rk);
    try testing.expectEqual(a3.result.rk, r.sk);
    try testing.expectEqual(kv.init_sk.*, r.rk);
    try testing.expectEqual(kv.init_rk.*, r.sk);
    try testing.expectEqual(kv.ck_temp_k3[0].*, r.ck);
    try testing.expectEqual(a3.result.handshake_hash, r.handshake_hash);
    try testing.expectEqual(kv.init_ls_pub.*, responder.rs_pub.?);

    // Transport round-trip over the freshly-derived keys: the initiator's
    // first message must be the published message-0 vector, and the
    // responder must decrypt it back.
    var itx = transport.Transport.init(a3.result);
    var rtx = transport.Transport.init(r);
    var wire: [transport.length_frame_len + 5 + 16]u8 = undefined;
    try itx.sendMessage("hello", &wire);
    try testing.expectEqualSlices(u8, kv.msg_outputs[0].bytes, &wire);
    const l = try rtx.recvLength(wire[0..transport.length_frame_len]);
    try testing.expectEqual(@as(u16, 5), l);
    var plain: [5]u8 = undefined;
    try rtx.recvMessage(wire[transport.length_frame_len..], &plain);
    try testing.expectEqualSlices(u8, "hello", &plain);
}

test "KAT: 'transport-initiator act2 bad MAC test' — readAct2 must fail closed with DecryptionFailed" {
    var initiator = try initiatorAfterAct1();
    try testing.expectError(error.DecryptionFailed, initiator.readAct2(try act.Act2.fromBytes(kv.act2_bad_mac)));
}

test "KAT: 'transport-responder act1 bad MAC test' — readAct1 must fail closed with DecryptionFailed" {
    const ls = try dh.KeyPair.generateDeterministic(kv.resp_ls_priv.*);
    var responder = handshake.Responder.init(ls);
    try testing.expectError(error.DecryptionFailed, responder.readAct1(try act.Act1.fromBytes(kv.act1_bad_mac)));
}

test "KAT: 'transport-responder act3 bad MAC for ciphertext test' — readAct3 must fail closed on the c field" {
    var responder = try responderAfterAct2();
    try testing.expectError(error.DecryptionFailed, responder.readAct3(try act.Act3.fromBytes(kv.act3_bad_ciphertext)));
}

test "KAT: 'transport-responder act3 bad MAC test' — readAct3 must fail closed on the t field" {
    var responder = try responderAfterAct2();
    try testing.expectError(error.DecryptionFailed, responder.readAct3(try act.Act3.fromBytes(kv.act3_bad_tag)));
}

test "KAT: 'transport-responder act3 bad rs test' — a decryptable-but-unparseable rs must abort (InvalidPublicKey)" {
    // The full crypto-level flow: readAct3 first decrypts `c` (its MAC
    // checks out — this is NOT a DecryptionFailed case), THEN must reject
    // because the recovered 33 bytes fail to parse as a valid SEC1 point
    // (same rejection class as kv.bad_recovered_static_key, real-tested
    // standalone in dh.zig).
    var responder = try responderAfterAct2();
    try testing.expectError(error.InvalidPublicKey, responder.readAct3(try act.Act3.fromBytes(kv.act3_bad_rs_message)));
    // The unvalidated key must NOT have been stored.
    try testing.expectEqual(@as(?[33]u8, null), responder.rs_pub);
}

// ── what IS real, cross-checked here as end-to-end wiring sanity ───────

test "wiring sanity: Transport built from the published sk/rk/ck reproduces the message-test outputs (delegates to transport.zig's own KAT)" {
    var t = transport.Transport.init(.{
        .sk = kv.init_sk.*,
        .rk = kv.init_rk.*,
        .ck = kv.ck_temp_k3[0].*,
        .handshake_hash = [_]u8{0} ** 32,
    });
    var out: [transport.length_frame_len + 5 + 16]u8 = undefined;
    try t.sendMessage("hello", &out);
    try testing.expectEqualSlices(u8, kv.msg_outputs[0].bytes, &out);
}

// ── differential: the AEAD swap must not move a single wire byte ───────
//
// `handshake.Suite` binds `noise.ChaCha20Poly1305` (the SIMD `chachapoly`
// sibling); `handshake.StdAeadSuite` binds `std.crypto.aead.chacha_poly.
// ChaCha20Poly1305`. Both are supposed to be the same function. Replay the
// published BOLT#8 "Message Encryption Tests" send sequence — same key, same
// chaining key, same nonce ladder, same rotation points — through a
// `CipherState` from EACH suite and require the produced frames to be equal
// to each other AND to the vectors BOLT#8 publishes.
//
// This drives the AEAD directly rather than through `Transport`, because
// `Transport` is bound to the one suite; the operations replicated here are
// exactly `Transport.sendMessage`'s two `encryptWithAd` calls plus the
// every-1000 `mixKey` rotation, so a divergence anywhere in the AEAD shows up
// as a mismatched frame.
fn bolt8SendSequence(comptime S: type, comptime n_msgs: usize, out_frames: *[n_msgs][18 + 5 + 16]u8) !void {
    var cipher: S.CipherState = .{};
    cipher.initializeKey(kv.msg_test_sk.*);
    var chain: [32]u8 = kv.msg_test_ck.*;

    for (0..n_msgs) |i| {
        var l_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &l_be, 5, .big);
        try cipher.encryptWithAd("", &l_be, out_frames[i][0..18]);
        if (cipher.n == 1000) {
            var shell: S.SymmetricState = .{ .ck = chain };
            shell.mixKey(&cipher.k);
            chain = shell.ck;
            cipher = shell.cipher_state;
        }
        try cipher.encryptWithAd("", "hello", out_frames[i][18..]);
        if (cipher.n == 1000) {
            var shell: S.SymmetricState = .{ .ck = chain };
            shell.mixKey(&cipher.k);
            chain = shell.ck;
            cipher = shell.cipher_state;
        }
    }
}

test "differential: BOLT#8 message-test frames are byte-identical under chachapoly and std, and match the published vectors" {
    // 1002 messages covers both published rotation boundaries (indices 500 and
    // 1001 in the vector table), so the differential spans a re-key too.
    const n = 1002;
    const Frames = [n][18 + 5 + 16]u8;
    const ours = try testing.allocator.create(Frames);
    defer testing.allocator.destroy(ours);
    const theirs = try testing.allocator.create(Frames);
    defer testing.allocator.destroy(theirs);

    try bolt8SendSequence(handshake.Suite, n, ours);
    try bolt8SendSequence(handshake.StdAeadSuite, n, theirs);

    for (0..n) |i| try testing.expectEqualSlices(u8, &theirs[i], &ours[i]);

    // …and both agree with the bytes BOLT#8 publishes.
    for (kv.msg_outputs) |o| {
        try testing.expectEqualSlices(u8, o.bytes, &ours[o.idx]);
        try testing.expectEqualSlices(u8, o.bytes, &theirs[o.idx]);
    }
}

test "wiring sanity: Initiator.init/Responder.init from the published identities agree (delegates to handshake.zig's own KAT)" {
    const init_ls = try dh.KeyPair.generateDeterministic(kv.init_ls_priv.*);
    const resp_ls = try dh.KeyPair.generateDeterministic(kv.resp_ls_priv.*);
    const initiator = handshake.Initiator.init(init_ls, kv.resp_ls_pub.*);
    const responder = handshake.Responder.init(resp_ls);
    try testing.expectEqual(initiator.ss.h, responder.ss.h);
    try testing.expectEqualSlices(u8, kv.ck_after_init, &initiator.ss.ck);
}
