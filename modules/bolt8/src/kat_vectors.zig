// SPDX-License-Identifier: MIT

//! The official BOLT#8 "Appendix A: Transport Test Vectors", embedded
//! verbatim from `lightning/bolts`, `08-transport.md` (raw GitHub,
//! `master` branch — see `../NOTICE`). Single source of truth: `dh.zig`,
//! `act.zig`, `transport.zig`, and `handshake.zig`'s own test blocks all
//! reference the `pub const`s below rather than re-embedding the same hex
//! literals, so there is exactly one place to update if the upstream spec
//! ever revises its vectors.
//!
//! Every value here was independently verified against the source file
//! (byte length + substring match) before being transcribed — see this
//! module's SPEC.md "Verification" section.

const std = @import("std");

pub fn hx(comptime s: []const u8) *const [s.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(1 << 16);
        var out: [s.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch unreachable;
        const frozen = out;
        return &frozen;
    }
}

// ── "transport-initiator successful handshake" / "transport-responder
//    successful handshake" — the two fixed identities + fixed ephemerals
//    BOLT#8 Appendix A uses in place of `generateKey()`'s randomness. ────

/// Initiator's static keypair.
pub const init_ls_priv = hx("1111111111111111111111111111111111111111111111111111111111111111");
pub const init_ls_pub = hx("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
/// Initiator's fixed ephemeral keypair (Act One).
pub const init_e_priv = hx("1212121212121212121212121212121212121212121212121212121212121212");
pub const init_e_pub = hx("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7");

/// Responder's static keypair — this IS `rs.pub` from the initiator's
/// point of view (`Noise_XK`'s pre-known responder static key).
pub const resp_ls_priv = hx("2121212121212121212121212121212121212121212121212121212121212121");
pub const resp_ls_pub = hx("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
/// Responder's fixed ephemeral keypair (Act Two).
pub const resp_e_priv = hx("2222222222222222222222222222222222222222222222222222222222222222");
pub const resp_e_pub = hx("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");

// ── the three acts' published wire bytes ─────────────────────────────────

/// Act One output (initiator -> responder), 50 bytes.
pub const act1_bytes = hx("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");
/// Act Two output (responder -> initiator), 50 bytes.
pub const act2_bytes = hx("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");
/// Act Three output (initiator -> responder), 66 bytes.
pub const act3_bytes = hx("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");

// ── intermediate values from the worked trace (`#` comments in the spec) ─

/// `ck` right after "Handshake State Initialization" (before Act One's
/// `e.pub` mixHash) — published as the first argument to Act One's
/// `HKDF(...)` comment, since `mixHash` never touches `ck`.
pub const ck_after_init = hx("2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1");

/// Act One's ECDH: `es = ECDH(init.e.priv, resp.ls.pub) == ECDH(resp.ls.priv, init.e.pub)`.
pub const ss_act1_es = hx("1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3");
/// Act Two's ECDH: `ee = ECDH(resp.e.priv, init.e.pub) == ECDH(init.e.priv, resp.e.pub)`.
pub const ss_act2_ee = hx("c06363d6cc549bcb7913dbb9ac1c33fc1158680c89e972000ecd06b36c472e47");
/// Act Three's ECDH: `se = ECDH(init.ls.priv, resp.e.pub) == ECDH(resp.e.priv, init.ls.pub)`.
pub const ss_act3_se = hx("b36b6d195982c5be874d6d542dc268234379e1ae4ff1709402135b7de5cf0766");

/// `ck`/`temp_k1` after Act One's `HKDF(ck, es)` (`mixKey(&ss_act1_es)`).
pub const ck_temp_k1 = .{ hx("b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f"), hx("e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f") };
/// `ck`/`temp_k2` after Act Two's `HKDF(ck, ee)`.
pub const ck_temp_k2 = .{ hx("e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba"), hx("908b166535c01a935cf1e130a5fe895ab4e6f3ef8855d87e9b7581c4ab663ddc") };
/// `ck`/`temp_k3` after Act Three's `HKDF(ck, se)` — this `ck` is also
/// `sck == rck`'s starting value (see `handshake.HandshakeResult.ck`).
pub const ck_temp_k3 = .{ hx("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"), hx("981a46c820fb7a241bc8184ba4bb1f01bcdfafb00dde80098cb8c38db9141520") };

/// Final transport keys, from the INITIATOR's perspective
/// (`sk` = initiator encrypts to responder, `rk` = initiator decrypts
/// from responder). The responder's own `readAct3` output publishes the
/// same two 32-byte values under the names `rk, sk` (swapped) — i.e.
/// `resp_rk == init_sk` and `resp_sk == init_rk`.
pub const init_sk = hx("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9");
pub const init_rk = hx("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442");

// ── negative vectors: framing-level (real, tested in act.zig) ──────────
//
// "transport-initiator act2 short read test" / "bad version test" and the
// responder-side act1/act3 short-read/bad-version mirrors are pure
// byte-shape mutations of `act1_bytes`/`act2_bytes`/`act3_bytes` above
// (truncate by 1 byte / flip the version byte to 0x01) — `act.zig`'s own
// tests construct them inline from these same constants rather than
// duplicating fresh hex literals.

/// "transport-initiator act2 bad key serialization test": act2's `e.pub`
/// byte patched from `0x02` to `0x04` (an uncompressed-form prefix with
/// only a 33-byte slot, one byte short of the 65 `fromSec1` would need) —
/// a pure parse-level rejection, real-testable via `dh.dh` directly
/// without touching the (stubbed) handshake driver.
pub const bad_pubkey_serialization = hx("04466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");

/// "transport-responder act3 bad rs test": the AEAD-decrypted `rs` comes
/// back with a `0x04` prefix instead of `0x02`/`0x03` — same class of
/// parse-level rejection as above, independent of the AEAD step that (in
/// the full handshake) recovers these bytes.
pub const bad_recovered_static_key = hx("044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");

// ── negative vectors: crypto-level (exercised via the handshake driver) ─
//
// These require an actual AEAD tag check to distinguish "wrong" from
// "right" — `kat_test.zig` runs each against the real `handshake.zig` act
// driver with the exact expected-error mapping asserted inline.

/// "transport-initiator act2 bad MAC test": act2's final tag byte
/// corrupted (`...730ae` -> `...730af`).
pub const act2_bad_mac = hx("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730af");
/// "transport-responder act1 bad MAC test": act1's final tag byte
/// corrupted (`...782c6a` -> `...782c6b`).
pub const act1_bad_mac = hx("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6b");
/// "transport-responder act3 bad MAC for ciphertext test": act3's `c`
/// field corrupted (first byte `0xb9` -> `0xc9`).
pub const act3_bad_ciphertext = hx("00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");
/// "transport-responder act3 bad MAC test": act3's final tag byte
/// corrupted (`...e139ba` -> `...e139bb`).
pub const act3_bad_tag = hx("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb");
/// "transport-responder act3 bad rs test": a FULL, alternate Act Three
/// message (different session) whose recovered `rs` fails to parse — the
/// crypto-level half of `bad_recovered_static_key` above (that constant is
/// just the already-decrypted 33 bytes; this is the full 66-byte wire
/// message the decrypt step itself must run on).
pub const act3_bad_rs_message = hx("00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c");

// ── "Message Encryption Tests" fixture (post-Act-Three transport state) ─

/// The initiator's post-handshake `ck` (== `sck` == `rck`'s starting
/// value), `sk`, `rk` — identical to `ck_temp_k3[0]`/`init_sk`/`init_rk`
/// above, repeated here under the spec's own "transport-message test"
/// fixture names for direct cross-reference against that section.
pub const msg_test_ck = ck_temp_k3[0];
pub const msg_test_sk = init_sk;
pub const msg_test_rk = init_rk;

/// One framed `lc || c` output per labeled test-vector index (0, 1, 500,
/// 501, 1000, 1001) — each a complete "hello" (5 bytes) message, spanning
/// two key-rotation boundaries (at message 500 and message 1000).
pub const MsgOutput = struct { idx: usize, bytes: []const u8 };
pub const msg_outputs = [_]MsgOutput{
    .{ .idx = 0, .bytes = hx("cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95") },
    .{ .idx = 1, .bytes = hx("72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1") },
    .{ .idx = 500, .bytes = hx("178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8") },
    .{ .idx = 501, .bytes = hx("1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd") },
    .{ .idx = 1000, .bytes = hx("4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09") },
    .{ .idx = 1001, .bytes = hx("2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36") },
};

/// The two published rotation intermediates: `(ck', k')` after the first
/// rotation (triggered when the message-0 key's nonce reaches 1000, i.e.
/// after message index 499's payload encrypt) and the second (after
/// message index 999's).
pub const RotationStep = struct { chain: []const u8, key: []const u8 };
pub const rotation_1 = RotationStep{
    .chain = hx("cc2c6e467efc8067720c2d09c139d1f77731893aad1defa14f9bf3c48d3f1d31"),
    .key = hx("3fbdc101abd1132ca3a0ae34a669d8d9ba69a587e0bb4ddd59524541cf4813d8"),
};
pub const rotation_2 = RotationStep{
    .chain = hx("728366ed68565dc17cf6dd97330a859a6a56e87e2beef3bd828a4c4a54d8df06"),
    .key = hx("9e0477f9850dca41e42db0e4d154e3a098e5a000d995e421849fcd5df27882bd"),
};

// ── tests: internal consistency of the transcribed data itself ─────────

const testing = std.testing;

test "vector lengths: 32-byte scalars/secrets, 33-byte pubkeys, 50/50/66-byte acts" {
    try testing.expectEqual(@as(usize, 32), init_ls_priv.len);
    try testing.expectEqual(@as(usize, 33), init_ls_pub.len);
    try testing.expectEqual(@as(usize, 32), init_e_priv.len);
    try testing.expectEqual(@as(usize, 33), init_e_pub.len);
    try testing.expectEqual(@as(usize, 32), resp_ls_priv.len);
    try testing.expectEqual(@as(usize, 33), resp_ls_pub.len);
    try testing.expectEqual(@as(usize, 32), resp_e_priv.len);
    try testing.expectEqual(@as(usize, 33), resp_e_pub.len);
    try testing.expectEqual(@as(usize, 50), act1_bytes.len);
    try testing.expectEqual(@as(usize, 50), act2_bytes.len);
    try testing.expectEqual(@as(usize, 66), act3_bytes.len);
    try testing.expectEqual(@as(usize, 32), init_sk.len);
    try testing.expectEqual(@as(usize, 32), init_rk.len);
}

test "msg_outputs: indices are strictly increasing and span both rotation boundaries" {
    var prev: usize = 0;
    for (msg_outputs, 0..) |o, i| {
        if (i > 0) try testing.expect(o.idx > prev);
        prev = o.idx;
    }
    try testing.expect(msg_outputs[2].idx > 499 and msg_outputs[3].idx > 499); // past 1st rotation
    try testing.expect(msg_outputs[4].idx > 999 and msg_outputs[5].idx > 999); // past 2nd rotation
}
