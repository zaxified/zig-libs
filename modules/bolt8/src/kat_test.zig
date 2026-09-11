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
    // Appendix A fixes `e.priv`, so this goes through the test-build-only
    // `genAct1WithEphemeral` hook — the ONLY way to pin the ephemeral since
    // the B6 seam audit; `genAct1` itself always draws from its `Ephemeral`.
    const a1 = try initiator.genAct1WithEphemeral(
        try dh.KeyPair.generateDeterministic(kv.init_e_priv.*),
    );
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
    const a2 = try responder.genAct2WithEphemeral(
        try dh.KeyPair.generateDeterministic(kv.resp_e_priv.*),
    );
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
    // Audit finding F1 (2026-09-05): the line above only ever compared the
    // two sides against EACH OTHER, which a value both sides compute the
    // same way will match even if computed wrong — two mutations that
    // replaced handshake_hash outright (with `ck`, and with an all-zero
    // constant) left this line green on both sides. Anchor against an
    // INDEPENDENTLY computed value instead (see `kv.handshake_hash_final`'s
    // doc comment for the recipe: a pure hash chain over published wire
    // bytes, no secret material).
    try testing.expectEqual(kv.handshake_hash_final.*, a3.result.handshake_hash);
    try testing.expectEqual(kv.init_ls_pub.*, responder.rs_pub.?);

    // Audit finding F7 (2026-09-05): the peer's identity (in Lightning, the
    // node id) used to live ONLY on the `Initiator`/`Responder` object,
    // never in `HandshakeResult` -- each side's result must now carry the
    // OTHER side's static public key, matching the published fixture keys.
    try testing.expectEqual(kv.resp_ls_pub.*, a3.result.remote_static); // initiator sees the responder's key
    try testing.expectEqual(kv.init_ls_pub.*, r.remote_static); // responder sees the initiator's key
    try testing.expectEqual(responder.rs_pub.?, r.remote_static);

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

// ── F5: a failed act kills the object, not just the one call ───────────────

test "F5: readAct3 failing on the t field does NOT leave rs_pub set, and re-entering any act returns WrongState" {
    var responder = try responderAfterAct2();
    try testing.expectEqual(handshake.Responder.State.awaiting_act3, responder.state);
    // Same vector as the KAT test above: `c` (carrying rs) decrypts fine —
    // rs_pub gets set from a VALIDATED key — and only the final tag over
    // the whole transcript fails.
    try testing.expectError(error.DecryptionFailed, responder.readAct3(try act.Act3.fromBytes(kv.act3_bad_tag)));
    // Before the fix: rs_pub stayed set to the peer's (unauthenticated,
    // since the handshake never actually completed) static key, and
    // `state` stayed `.awaiting_act3` -- re-enterable over a
    // half-mutated SymmetricState.
    try testing.expectEqual(@as(?[33]u8, null), responder.rs_pub);
    try testing.expectEqual(handshake.Responder.State.failed, responder.state);
    // The object is dead now, not just "still waiting": neither a retry of
    // the failed act nor the genuine one that would have worked is let
    // through.
    try testing.expectError(error.WrongState, responder.readAct3(try act.Act3.fromBytes(kv.act3_bad_tag)));
    try testing.expectError(error.WrongState, responder.readAct3(try act.Act3.fromBytes(kv.act3_bytes)));
}

test "F5: readAct2 failing kills the initiator too, even though the transcript already moved" {
    var initiator = try initiatorAfterAct1();
    const h_before = initiator.ss.h;
    try testing.expectError(error.DecryptionFailed, initiator.readAct2(try act.Act2.fromBytes(kv.act2_bad_mac)));
    // The transcript hash moved (mixHash(&msg.e_pub) ran unconditionally
    // before the MAC check) even though the message was rejected -- that
    // part is inherent to the protocol shape, not the bug. The bug was that
    // `state` used to stay `.awaiting_act2` afterward, so the object looked
    // untouched from the outside.
    try testing.expect(!std.mem.eql(u8, &h_before, &initiator.ss.h));
    try testing.expectEqual(handshake.Initiator.State.failed, initiator.state);
    // Neither a retry of the bad message nor the genuine Act Two that
    // would have worked is let through anymore.
    try testing.expectError(error.WrongState, initiator.readAct2(try act.Act2.fromBytes(kv.act2_bad_mac)));
    try testing.expectError(error.WrongState, initiator.readAct2(try act.Act2.fromBytes(kv.act2_bytes)));
}

test "KAT: 'transport-responder act1 bad key serialization test' — readAct1 must reject a malformed e.pub prefix" {
    // Audit finding F4 (2026-09-05): of BOLT#8's 16 named test vectors, this
    // was the one embedded nowhere and exercised nowhere. The module
    // rejects it correctly today -- this pins that against regression.
    const ls = try dh.KeyPair.generateDeterministic(kv.resp_ls_priv.*);
    var responder = handshake.Responder.init(ls);
    try testing.expectError(error.InvalidPublicKey, responder.readAct1(try act.Act1.fromBytes(kv.act1_bad_key_serialization)));
    // Sanity check on the vector itself: exactly one byte different from
    // the accepted `act1_bytes` (the e.pub SEC1 prefix, index 1), so this
    // is genuinely testing key-serialization rejection and not some other
    // accidental difference.
    var diffs: usize = 0;
    for (kv.act1_bytes, kv.act1_bad_key_serialization, 0..) |a, b, i| {
        if (a != b) {
            try testing.expectEqual(@as(usize, 1), i);
            diffs += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), diffs);
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
        .remote_static = [_]u8{0} ** 33,
    });
    var out: [transport.length_frame_len + 5 + 16]u8 = undefined;
    try t.sendMessage("hello", &out);
    try testing.expectEqualSlices(u8, kv.msg_outputs[0].bytes, &out);
}

test "README 'post-handshake transport' snippet, verbatim, with real types (F9 2026-09-05: it used to fail to compile)" {
    // Audit finding F12 (2026-09-05): `var plain: [l]u8 = undefined;` where
    // `l` is `Transport.recvLength`'s runtime `u16` result -- "unable to
    // resolve comptime value". This is the corrected form, kept in the real
    // suite (not just the doc) so it cannot silently rot again.
    var sender = transport.Transport.init(.{
        .sk = kv.init_sk.*,
        .rk = kv.init_rk.*,
        .ck = kv.ck_temp_k3[0].*,
        .handshake_hash = [_]u8{0} ** 32,
        .remote_static = [_]u8{0} ** 33,
    });
    var receiver = transport.Transport.init(.{
        .sk = kv.init_rk.*,
        .rk = kv.init_sk.*,
        .ck = kv.ck_temp_k3[0].*,
        .handshake_hash = [_]u8{0} ** 32,
        .remote_static = [_]u8{0} ** 33,
    });
    const msg = "hello";
    var out: [transport.length_frame_len + msg.len + 16]u8 = undefined;
    try sender.sendMessage(msg, &out);

    const l = try receiver.recvLength(out[0..transport.length_frame_len]);
    var buf: [transport.max_message_len]u8 = undefined; // caller-owned upper bound
    const plain = buf[0..l]; // `l` is runtime, so this must be a SLICE, not an array length
    try receiver.recvMessage(out[transport.length_frame_len..], plain);
    try testing.expectEqualStrings(msg, plain);
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

test "F2: deinit zeroes the key material each object directly owns" {
    // Audit finding F2 (2026-09-05): the module had no zeroization at all.
    // This does not claim the dead stack is clean (see SPEC.md's note on
    // that) -- only that the LIVE fields on these objects go to zero.
    var initiator = try initiatorAfterAct1();
    try testing.expect(!std.mem.allEqual(u8, &initiator.ls.secret_key, 0));
    try testing.expect(!std.mem.allEqual(u8, &initiator.ephemeral.?.secret_key, 0));
    initiator.deinit();
    try testing.expect(std.mem.allEqual(u8, &initiator.ls.secret_key, 0));
    try testing.expect(std.mem.allEqual(u8, &initiator.ephemeral.?.secret_key, 0));
    try testing.expect(std.mem.allEqual(u8, &initiator.ss.ck, 0));
    try testing.expect(std.mem.allEqual(u8, &initiator.ss.cipher_state.k, 0));

    var responder = try responderAfterAct2();
    try testing.expect(!std.mem.allEqual(u8, &responder.ls.secret_key, 0));
    responder.deinit();
    try testing.expect(std.mem.allEqual(u8, &responder.ls.secret_key, 0));
    try testing.expect(std.mem.allEqual(u8, &responder.ss.ck, 0));

    var t = transport.Transport.init(.{ .sk = kv.init_sk.*, .rk = kv.init_rk.*, .ck = kv.ck_temp_k3[0].*, .handshake_hash = [_]u8{0} ** 32, .remote_static = [_]u8{0} ** 33 });
    try testing.expect(!std.mem.allEqual(u8, &t.tx.cipher.k, 0));
    t.deinit();
    try testing.expect(std.mem.allEqual(u8, &t.tx.cipher.k, 0));
    try testing.expect(std.mem.allEqual(u8, &t.tx.chain, 0));
    try testing.expect(std.mem.allEqual(u8, &t.rx.cipher.k, 0));
    try testing.expect(std.mem.allEqual(u8, &t.rx.chain, 0));
}
