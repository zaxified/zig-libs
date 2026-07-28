// SPDX-License-Identifier: MIT
//! mls.kat_welcome_test — the official RFC 9420 `welcome` interop vector
//! (`mlswg/mls-implementations` `test-vectors/welcome.json`), driving the
//! whole §12.4.3.1 joining path with real keys. Embedded verbatim; see
//! `NOTICE` for the source commit and fetch date.
//!
//! **This harness goes one step past upstream's own procedure.** Upstream
//! says to decrypt the `GroupSecrets`, decrypt the `GroupInfo`, verify its
//! signature and recompute its `confirmation_tag` — all RECEIVE-direction
//! checks, because a generic implementation cannot reproduce a Welcome it
//! did not create. But the group-info layer is not randomized: §12.4.3.1
//! derives its AEAD key and nonce deterministically from `welcome_secret`
//! and specifies no associated data, and AES-GCM with a fixed key and nonce
//! is a function. So once `joiner_secret` has been recovered from the HPKE
//! layer, this harness RE-ENCRYPTS the decrypted `GroupInfo` and requires
//! the result to equal the vector's own `encrypted_group_info` byte for
//! byte. A receive-only test passes with a systematically wrong
//! `welcome_secret` derivation as long as it is wrong in the same way in
//! both directions; this cannot.
//!
//! **What is round-trip only, and why.** The per-member layer
//! (`EncryptWithLabel(init_key, "Welcome", ...)`) cannot be reproduced from
//! this vector in the send direction: HPKE draws a fresh ephemeral KEM
//! keypair per encryption, and the vector publishes only the resulting
//! `kem_output` (the ephemeral PUBLIC key). Recovering the ephemeral
//! private key from it is the discrete log. That layer is therefore checked
//! in the receive direction here, and round-trip only in `welcome.zig`'s own
//! `encryptGroupSecrets/decryptGroupSecrets` test — stated plainly rather
//! than papered over. The same applies to the `GroupInfo` SIGNATURE: the
//! vector publishes `signer_pub` and no private key, so signing is verified
//! against a self-produced signature in `welcome.zig`, not against these
//! bytes.
//!
//! Every check is staged, so a divergence names the layer that diverged —
//! the KeyPackageRef, the HPKE open, the welcome-key derivation, the
//! group-info AEAD, the signature, or the confirmation tag.
//!
//! Parsed as generic `std.json.Value`, matching `kat_test.zig`'s reasoning.

const std = @import("std");
const codec = @import("codec.zig");
const crypto = @import("crypto.zig");
const suite = @import("suite.zig");
const framing = @import("framing.zig");
const keypackage = @import("keypackage.zig");
const keyschedule = @import("keyschedule.zig");
const transcript = @import("transcript.zig");
const welcome = @import("welcome.zig");

const welcome_json = @embedFile("data/welcome.json");

const testing = std.testing;
const S = suite.default;

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn asI64(v: std.json.Value) i64 {
    return switch (v) {
        .integer => |i| i,
        else => unreachable,
    };
}

fn expectStage(stage: []const u8, want: []const u8, got: []const u8) !void {
    testing.expectEqualSlices(u8, want, got) catch |err| {
        std.debug.print(
            "welcome KAT: '{s}' diverged (want {d} bytes, got {d})\n",
            .{ stage, want.len, got.len },
        );
        return err;
    };
}

fn expectStageOk(stage: []const u8, result: anyerror!void) !void {
    result catch |err| {
        std.debug.print("welcome KAT: '{s}' failed: {s}\n", .{ stage, @errorName(err) });
        return err;
    };
}

/// One vector entry, decoded into the four things every test below needs.
/// The returned slices alias `arena`; `key_package_bytes` is the WHOLE
/// `MLSMessage(KeyPackage)` and `key_package_body` is that message minus its
/// four-byte header, which is what §5.2's `MakeKeyPackageRef` hashes.
const Entry = struct {
    key_package_bytes: []u8,
    welcome_bytes: []u8,
    init_key_pair: S.Kem.KeyPair,
    signer_pub: S.Sig.PublicKey,
};

fn loadEntry(arena: std.mem.Allocator, obj: std.json.ObjectMap) !Entry {
    var init_priv: [S.Kem.Nsk]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&init_priv, obj.get("init_priv").?.string);
    try testing.expectEqual(@as(usize, S.Kem.Nsk), decoded.len);

    var signer_pub_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&signer_pub_bytes, obj.get("signer_pub").?.string);

    return .{
        .key_package_bytes = try hexDecode(arena, obj.get("key_package").?.string),
        .welcome_bytes = try hexDecode(arena, obj.get("welcome").?.string),
        // `init_priv` is a raw X25519 scalar, so the public half is
        // recovered from it rather than read from the vector — and the
        // KeyPackage's `init_key` check below is what pins that reading.
        .init_key_pair = try S.Kem.KeyPair.generateDeterministic(init_priv),
        .signer_pub = try S.Sig.PublicKey.fromBytes(signer_pub_bytes),
    };
}

/// §5.2's `MakeKeyPackageRef` over the KeyPackage the vector's
/// `MLSMessage(KeyPackage)` carries. The `MLSMessage` header is NOT part of
/// the hashed value (§5.2 hashes a `KeyPackage`, not its envelope), so the
/// KeyPackage is re-encoded from the decoded struct — which the surrounding
/// byte-exact re-encode check makes safe.
fn keyPackageRef(allocator: std.mem.Allocator, kp: keypackage.KeyPackage) ![S.Hash.digest_length]u8 {
    const bytes = try kp.encodeAlloc(allocator);
    defer allocator.free(bytes);
    return crypto.make_keypackage_ref(S, bytes);
}

test "welcome.json: RFC 9420 §12.4.3.1's whole joining path for suite 0x0001, byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, welcome_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();
    const alloc = testing.allocator;

    var found_suite_1 = false;
    var skipped_other_suites: usize = 0;

    for (parsed.value.array.items) |entry| {
        const obj = entry.object;
        if (asI64(obj.get("cipher_suite").?) != @as(i64, @intFromEnum(S.id))) {
            skipped_other_suites += 1;
            continue; // this module only wires suite 0x0001 — see suite.zig
        }
        found_suite_1 = true;

        const e = try loadEntry(arena, obj);

        // ── the caller's own KeyPackage ──
        var kp_reader = codec.Reader.init(e.key_package_bytes);
        const kp_msg = try framing.MLSMessage.decode(alloc, &kp_reader);
        defer kp_msg.deinit(alloc);
        try testing.expect(kp_reader.atEnd());
        const kp = kp_msg.key_package;
        {
            const re = try kp_msg.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectStage("key_package re-encode", e.key_package_bytes, re);
        }
        try testing.expectEqual(S.id, kp.cipher_suite);
        // `init_priv` really is the private half of THIS KeyPackage's
        // `init_key` — otherwise the HPKE open below would fail for a
        // reason ("wrong key") the AEAD cannot distinguish from any other.
        try expectStage("init_priv -> KeyPackage.init_key", kp.init_key, &e.init_key_pair.public_key);
        // §10's self-signature, which is the only thing making the
        // KeyPackageRef below meaningful as an identifier.
        try expectStageOk("KeyPackage self-signature (§10)", kp.verifySignature(S, alloc));

        const kp_ref = try keyPackageRef(alloc, kp);

        // ── §12.4.3.1: the Welcome ──
        var w_reader = codec.Reader.init(e.welcome_bytes);
        const w_msg = try framing.MLSMessage.decode(alloc, &w_reader);
        defer w_msg.deinit(alloc);
        try testing.expect(w_reader.atEnd());
        const w = w_msg.welcome;
        {
            const re = try w_msg.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectStage("welcome re-encode", e.welcome_bytes, re);
        }
        try testing.expectEqual(S.id, w.cipher_suite);

        // Step 1: our slot. Finding it is a real check of §5.2 — the
        // vector's `new_member` was computed by another implementation's
        // `MakeKeyPackageRef` over its own encoding of the same KeyPackage.
        const slot = w.findSecret(&kp_ref) orelse {
            std.debug.print("welcome KAT: 'KeyPackageRef (§5.2)' matched no entry in welcome.secrets\n", .{});
            return error.NoMatchingKeyPackage;
        };

        // Step 2: HPKE-open the GroupSecrets, with the whole
        // `encrypted_group_info` as the EncryptWithLabel context.
        const gs_bytes = welcome.decryptGroupSecrets(S, alloc, e.init_key_pair, w.encrypted_group_info, slot.encrypted_group_secrets) catch |err| {
            std.debug.print("welcome KAT: 'GroupSecrets HPKE open (§12.4.3.1)' failed: {s}\n", .{@errorName(err)});
            return err;
        };
        defer alloc.free(gs_bytes);

        var gs_reader = codec.Reader.init(gs_bytes);
        const gs = try welcome.GroupSecrets.decode(alloc, &gs_reader);
        defer gs.deinit(alloc);
        try testing.expect(gs_reader.atEnd());
        {
            const re = try gs.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectStage("GroupSecrets re-encode", gs_bytes, re);
        }
        try testing.expectEqual(@as(usize, S.Nh), gs.joiner_secret.len);

        // Step 3: joiner_secret -> welcome_secret -> the GroupInfo.
        // Upstream's procedure says "no PSKs" for this vector, so
        // `psk_secret` is §8.4's all-zero psk_secret_[0].
        var joiner: [S.Nh]u8 = undefined;
        @memcpy(&joiner, gs.joiner_secret);
        try testing.expectEqual(@as(usize, 0), gs.psks.len);
        const welcome_secret = try keyschedule.welcomeSecret(S, joiner, keyschedule.zeroSecret(S));

        const gi_bytes = welcome.decryptGroupInfo(S, alloc, welcome_secret, w.encrypted_group_info) catch |err| {
            std.debug.print("welcome KAT: 'GroupInfo AEAD (§12.4.3.1 welcome_key/nonce)' failed: {s}\n", .{@errorName(err)});
            return err;
        };
        defer alloc.free(gi_bytes);

        // ── the SEND direction of this layer, byte-exact (see the module
        // doc comment) ──
        {
            const resealed = try welcome.encryptGroupInfo(S, alloc, welcome_secret, gi_bytes);
            defer alloc.free(resealed);
            try expectStage("encryptGroupInfo -> encrypted_group_info", w.encrypted_group_info, resealed);
        }

        var gi_reader = codec.Reader.init(gi_bytes);
        const gi = try welcome.GroupInfo.decode(alloc, &gi_reader);
        defer gi.deinit(alloc);
        try testing.expect(gi_reader.atEnd());
        {
            const re = try gi.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectStage("GroupInfo re-encode", gi_bytes, re);
        }

        // Step 4: the signature, over the RAW received TBS prefix.
        try expectStageOk("GroupInfo signature (§12.4.3 GroupInfoTBS)", gi.verifySignature(S, alloc, e.signer_pub));
        try testing.expectEqual(S.id, gi.group_context.cipher_suite);

        // Step 5: the epoch, entered at joiner_secret, and the
        // confirmation tag that is what makes taking it on trust sound.
        const secrets = try keyschedule.deriveEpochFromJoiner(S, alloc, joiner, keyschedule.zeroSecret(S), gi.raw.?.group_context);
        try expectStage("joiner_secret round-trips through EpochSecrets", gs.joiner_secret, &joiner);
        try expectStageOk("confirmation_tag (§6.1/§12.4.3)", keyschedule.verifyConfirmationTag(
            S,
            secrets.confirmation_key,
            gi.group_context.confirmed_transcript_hash,
            gi.confirmation_tag,
        ));

        // ── and the same thing again through the one-call entry point,
        // which must agree with the hand-staged path above in every field ──
        var joined = welcome.join(S, alloc, .{
            .welcome = w,
            .key_package_ref = &kp_ref,
            .init_key_pair = e.init_key_pair,
            .signer_key = e.signer_pub,
        }) catch |err| {
            std.debug.print("welcome KAT: 'welcome.join (§12.4.3.1 end to end)' failed: {s}\n", .{@errorName(err)});
            return err;
        };
        defer joined.deinit(alloc);

        try expectStage("join -> GroupInfo bytes", gi_bytes, joined.group_info_bytes);
        try expectStage("join -> GroupSecrets bytes", gs_bytes, joined.group_secrets_bytes);
        try expectStage("join -> epoch_secret", &secrets.epoch_secret, &joined.secrets.epoch_secret);
        try expectStage("join -> epoch_authenticator", &secrets.epoch_authenticator, &joined.secrets.epoch_authenticator);
        try expectStage("join -> init_secret (next epoch)", &secrets.init_secret, &joined.secrets.init_secret);

        // §8.2's interim hash for the epoch the joiner landed in — the one
        // value a joiner computes differently from everyone else, since it
        // never saw the Commit.
        const interim = try transcript.interimTranscriptHash(S, gi.group_context.confirmed_transcript_hash, gi.confirmation_tag);
        try expectStage("join -> interim_transcript_hash (§8.2)", &interim, &joined.interim_transcript_hash);
    }

    try testing.expect(found_suite_1);
    // Suites 0x0002-0x0007 each contribute one entry.
    try testing.expectEqual(@as(usize, 6), skipped_other_suites);
}

test "welcome.json: each layer's teeth — one flipped byte fails the layer it belongs to and no other" {
    // The point of this test is that a corruption at each of the four
    // stages produces the error NAMED FOR THAT STAGE, so a future
    // divergence can be localized instead of reported as "the vector
    // failed". Every case restores the original bytes by working on a
    // fresh copy.
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, welcome_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();
    const alloc = testing.allocator;

    for (parsed.value.array.items) |entry| {
        const obj = entry.object;
        if (asI64(obj.get("cipher_suite").?) != @as(i64, @intFromEnum(S.id))) continue;

        const e = try loadEntry(arena, obj);

        var kp_reader = codec.Reader.init(e.key_package_bytes);
        const kp_msg = try framing.MLSMessage.decode(alloc, &kp_reader);
        defer kp_msg.deinit(alloc);
        const kp_ref = try keyPackageRef(alloc, kp_msg.key_package);

        var w_reader = codec.Reader.init(e.welcome_bytes);
        const w_msg = try framing.MLSMessage.decode(alloc, &w_reader);
        defer w_msg.deinit(alloc);
        const w = w_msg.welcome;
        const slot = w.findSecret(&kp_ref).?;

        // (a) The KeyPackageRef layer: one flipped byte in the ref and no
        // slot matches at all — this is what proves `findSecret` is
        // comparing the ref rather than taking `secrets[0]`.
        {
            var bad_ref = kp_ref;
            bad_ref[0] ^= 0x01;
            try testing.expect(w.findSecret(&bad_ref) == null);
            try testing.expectError(error.NoMatchingKeyPackage, welcome.join(S, alloc, .{
                .welcome = w,
                .key_package_ref = &bad_ref,
                .init_key_pair = e.init_key_pair,
                .signer_key = e.signer_pub,
            }));
        }

        // (b) The HPKE layer: one flipped byte in the sealed GroupSecrets.
        {
            const tampered = try alloc.dupe(u8, slot.encrypted_group_secrets.ciphertext);
            defer alloc.free(tampered);
            tampered[tampered.len / 2] ^= 0x01;
            try testing.expectError(error.DecryptionFailed, welcome.decryptGroupSecrets(
                S,
                alloc,
                e.init_key_pair,
                w.encrypted_group_info,
                .{ .kem_output = slot.encrypted_group_secrets.kem_output, .ciphertext = tampered },
            ));
        }

        // (b') The BINDING between the two layers: leave the sealed
        // GroupSecrets untouched and flip one byte of the
        // `encrypted_group_info` used as its EncryptWithLabel context. If
        // the context were dropped, this would still open.
        {
            const tampered_ctx = try alloc.dupe(u8, w.encrypted_group_info);
            defer alloc.free(tampered_ctx);
            tampered_ctx[0] ^= 0x01;
            try testing.expectError(error.DecryptionFailed, welcome.decryptGroupSecrets(
                S,
                alloc,
                e.init_key_pair,
                tampered_ctx,
                slot.encrypted_group_secrets,
            ));
        }

        // Recover the real secrets for the remaining cases.
        const gs_bytes = try welcome.decryptGroupSecrets(S, alloc, e.init_key_pair, w.encrypted_group_info, slot.encrypted_group_secrets);
        defer alloc.free(gs_bytes);
        var gs_reader = codec.Reader.init(gs_bytes);
        const gs = try welcome.GroupSecrets.decode(alloc, &gs_reader);
        defer gs.deinit(alloc);
        var joiner: [S.Nh]u8 = undefined;
        @memcpy(&joiner, gs.joiner_secret);
        const zero = keyschedule.zeroSecret(S);
        const welcome_secret = try keyschedule.welcomeSecret(S, joiner, zero);

        // (c) The group-info AEAD layer.
        {
            const tampered = try alloc.dupe(u8, w.encrypted_group_info);
            defer alloc.free(tampered);
            tampered[tampered.len / 2] ^= 0x01;
            try testing.expectError(error.DecryptionFailed, welcome.decryptGroupInfo(S, alloc, welcome_secret, tampered));
        }

        const gi_bytes = try welcome.decryptGroupInfo(S, alloc, welcome_secret, w.encrypted_group_info);
        defer alloc.free(gi_bytes);
        var gi_reader = codec.Reader.init(gi_bytes);
        const gi = try welcome.GroupInfo.decode(alloc, &gi_reader);
        defer gi.deinit(alloc);

        // (d) The signature layer: one flipped byte inside the signed TBS
        // prefix. Flipping the raw plaintext is the strongest form of this
        // — it proves the verification really reads the received bytes and
        // not a re-encode of the decoded struct.
        {
            const tampered = try alloc.dupe(u8, gi_bytes);
            defer alloc.free(tampered);
            tampered[tampered.len / 2] ^= 0x01;
            var r = codec.Reader.init(tampered);
            const bad_gi = welcome.GroupInfo.decode(alloc, &r) catch continue;
            defer bad_gi.deinit(alloc);
            try testing.expectError(
                error.SignatureVerificationFailed,
                bad_gi.verifySignature(S, alloc, e.signer_pub),
            );
        }

        // (e) The key-schedule layer, which is the deepest one: flip one
        // bit of `joiner_secret` and the CONFIRMATION TAG — not the
        // signature, not any AEAD — is what rejects it. This is the check
        // that the epoch a joiner lands in is really pinned to the group's.
        {
            var bad_joiner = joiner;
            bad_joiner[0] ^= 0x01;
            const bad_secrets = try keyschedule.deriveEpochFromJoiner(S, alloc, bad_joiner, zero, gi.raw.?.group_context);
            try testing.expectError(error.MacMismatch, keyschedule.verifyConfirmationTag(
                S,
                bad_secrets.confirmation_key,
                gi.group_context.confirmed_transcript_hash,
                gi.confirmation_tag,
            ));
            // ...and the correct one still passes, so the case above is a
            // real rejection rather than a broken derivation.
            const good_secrets = try keyschedule.deriveEpochFromJoiner(S, alloc, joiner, zero, gi.raw.?.group_context);
            try keyschedule.verifyConfirmationTag(
                S,
                good_secrets.confirmation_key,
                gi.group_context.confirmed_transcript_hash,
                gi.confirmation_tag,
            );
        }

        // (f) And the group context itself: the epoch is derived over the
        // SIGNED GroupContext, so a joiner fed a different one derives a
        // different epoch. Re-encoding a modified GroupContext is the
        // cheapest way to show the binding is real.
        {
            var bad_gc = gi.group_context;
            bad_gc.epoch += 1;
            const bad_bytes = try bad_gc.encodeAlloc(alloc);
            defer alloc.free(bad_bytes);
            const bad_secrets = try keyschedule.deriveEpochFromJoiner(S, alloc, joiner, zero, bad_bytes);
            try testing.expectError(error.MacMismatch, keyschedule.verifyConfirmationTag(
                S,
                bad_secrets.confirmation_key,
                gi.group_context.confirmed_transcript_hash,
                gi.confirmation_tag,
            ));
        }
        return;
    }
    return error.SkipZigTest;
}
