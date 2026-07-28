// SPDX-License-Identifier: MIT
//! mls.kat_framing_test — the two official RFC 9420 interop vectors that
//! pin Part 5's CRYPTOGRAPHIC behaviour rather than just its wire shapes:
//! `message-protection.json` (the whole §6 protect/unprotect path, with
//! real keys) and `transcript-hashes.json` (§8.2). Both embedded verbatim;
//! see `NOTICE` for source commit and fetch date.
//!
//! **Why these two and not just `messages.json`.** `messages.json` (see
//! `kat_messages_test.zig`) carries no keys, so its MACs and signatures are
//! explicitly allowed to be garbage. These two carry the keys, so every
//! derivation in the path is checked against another implementation's
//! output: the signature over `FramedContentTBS`, the `membership_tag` over
//! `AuthenticatedContentTBM`, the §9.1 ratchet key/nonce, the §6.3.1 reuse
//! guard, the §6.3.2 sender-data key sampled from the ciphertext, and both
//! §8.2 hashes.
//!
//! **This harness checks protection BYTE-EXACT in both directions, which is
//! more than upstream's own procedure asks for.** Upstream says to verify
//! that protecting "produces a PublicMessage that verifies" — a round-trip,
//! because a generic implementation picks a random reuse guard and an
//! arbitrary padding length, so its output cannot be compared to the
//! vector's. But every one of those choices is RECOVERABLE from the vector
//! itself: the reuse guard comes out of the decrypted `SenderData`, the
//! generation with it, and the padding length is the decrypted plaintext
//! length minus the encoded body and auth. Feed those back in and the whole
//! construction is deterministic — Ed25519 is (RFC 8032) and AES-GCM is,
//! given key/nonce/AAD — so this harness reproduces `proposal_pub`,
//! `commit_pub`, `proposal_priv`, `commit_priv` and `application_priv`
//! byte-for-byte. A round-trip test would pass with a systematically wrong
//! `FramedContentTBS`; this cannot.
//!
//! Every check is staged, so a divergence names the derivation that
//! diverged (the signature, the membership tag, the content AEAD, the
//! sender-data AEAD, or the final encoding) rather than "the vector
//! failed".
//!
//! Parsed as generic `std.json.Value`, matching `kat_test.zig`'s reasoning.

const std = @import("std");
const codec = @import("codec.zig");
const suite = @import("suite.zig");
const content = @import("content.zig");
const framing = @import("framing.zig");
const keyschedule = @import("keyschedule.zig");
const secrettree = @import("secrettree.zig");
const transcript = @import("transcript.zig");

const message_protection_json = @embedFile("data/message-protection.json");
const transcript_hashes_json = @embedFile("data/transcript-hashes.json");

const testing = std.testing;
const S = suite.default;

/// `message-protection.json`'s procedure: "Initialize a secret tree for 2
/// members with the specified encryption_secret" and "use the member with
/// LeafIndex 1 as the sender".
const vector_group_size: usize = 2;
const vector_sender_leaf: u32 = 1;

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hexSecret(hex: []const u8) ![S.Nh]u8 {
    var out: [S.Nh]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&out, hex);
    try testing.expectEqual(@as(usize, S.Nh), decoded.len);
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
            "framing KAT: '{s}' diverged (want {d} bytes, got {d})\n",
            .{ stage, want.len, got.len },
        );
        return err;
    };
}

/// Names the stage for a failure that is an ERROR rather than a byte
/// mismatch — a MAC/signature rejection or an AEAD failure. Without this,
/// the two `inline for` loops below would report a bare `error.MacMismatch`
/// with no indication of which content type or which of the two tags it
/// came from, since every iteration shares one source line.
fn expectStageOk(name: []const u8, result: anyerror!void) !void {
    result catch |err| {
        std.debug.print("framing KAT: '{s}' failed: {s}\n", .{ name, @errorName(err) });
        return err;
    };
}

/// The vector's raw `proposal`/`commit`/`application` field re-encoded from
/// whatever body came out of the message — the mapping is per content type,
/// because `application` is bare payload bytes while the other two are
/// their own serialized structures.
fn encodeBodyAlloc(allocator: std.mem.Allocator, body: framing.FramedContentBody) ![]u8 {
    return switch (body) {
        .application => |d| allocator.dupe(u8, d),
        .proposal => |p| p.encodeAlloc(allocator),
        .commit => |c| c.encodeAlloc(allocator),
    };
}

/// The §9.1 ratchet key/nonce for `generation` of `leaf`'s handshake or
/// application ratchet, in a tree of `vector_group_size` leaves.
fn ratchetKeyNonce(
    encryption_secret: [S.Nh]u8,
    leaf: u32,
    kind: secrettree.RatchetKind,
    generation: u32,
) !secrettree.KeyNonce(S) {
    const base = try secrettree.ratchetBaseSecret(S, encryption_secret, vector_group_size, leaf, kind);
    var ratchet = secrettree.Ratchet(S).init(base);
    while (ratchet.generation < generation) try ratchet.advance();
    return ratchet.current();
}

test "message-protection.json: RFC 9420 §6's whole protect/unprotect path for suite 0x0001, byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, message_protection_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();
    const alloc = testing.allocator;

    var found_suite_1 = false;
    var skipped_other_suites: usize = 0;
    var public_checked: usize = 0;
    var private_checked: usize = 0;

    for (parsed.value.array.items) |entry| {
        const obj = entry.object;
        if (asI64(obj.get("cipher_suite").?) != @as(i64, @intFromEnum(S.id))) {
            skipped_other_suites += 1;
            continue; // this module only wires suite 0x0001 — see suite.zig
        }
        found_suite_1 = true;

        // ── the group state the vector's procedure prescribes ──
        const group_id = try hexDecode(arena, obj.get("group_id").?.string);
        const gc: keyschedule.GroupContext = .{
            .cipher_suite = S.id,
            .group_id = group_id,
            .epoch = @intCast(asI64(obj.get("epoch").?)),
            .tree_hash = try hexDecode(arena, obj.get("tree_hash").?.string),
            .confirmed_transcript_hash = try hexDecode(arena, obj.get("confirmed_transcript_hash").?.string),
            .extensions = &.{}, // "and empty extensions"
        };
        const gc_bytes = try gc.encodeAlloc(alloc);
        defer alloc.free(gc_bytes);

        const membership_key = try hexSecret(obj.get("membership_key").?.string);
        const encryption_secret = try hexSecret(obj.get("encryption_secret").?.string);
        const sender_data_secret = try hexSecret(obj.get("sender_data_secret").?.string);

        // `signature_priv` is the Ed25519 SEED (RFC 8032 §5.1.5's 32-byte
        // private key), not an expanded scalar — asserting that the derived
        // public key matches `signature_pub` is what pins that reading.
        var seed: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&seed, obj.get("signature_priv").?.string);
        const key_pair = try S.Sig.KeyPair.generateDeterministic(seed);
        const pub_bytes = key_pair.public_key.toBytes();
        try expectStage("signature_priv -> signature_pub", try hexDecode(arena, obj.get("signature_pub").?.string), &pub_bytes);
        const signature_pub = key_pair.public_key;

        // ── §6.2: PublicMessage, for the two handshake content types ──
        inline for (.{
            .{ "proposal", "proposal_pub" },
            .{ "commit", "commit_pub" },
        }) |spec| {
            const raw = try hexDecode(arena, obj.get(spec[0]).?.string);
            const vec = try hexDecode(arena, obj.get(spec[1]).?.string);

            var r = codec.Reader.init(vec);
            const msg = try framing.MLSMessage.decode(alloc, &r);
            defer msg.deinit(alloc);
            try testing.expect(r.atEnd());
            const pm = msg.public_message;

            // Unprotect: both §6.2 MUSTs, in the order the RFC states them.
            try expectStageOk(spec[1] ++ " membership_tag (§6.2)", framing.verifyMembershipTag(S, alloc, membership_key, pm, gc_bytes));
            try expectStageOk(spec[1] ++ " signature (§6.1)", framing.verifyFramedContent(S, alloc, signature_pub, pm.authenticatedContent(), gc_bytes));
            try testing.expectEqual(vector_sender_leaf, pm.content.sender.member);

            // ...and it really does carry the vector's raw proposal/commit.
            const body = try encodeBodyAlloc(alloc, pm.content.body);
            defer alloc.free(body);
            try expectStage(spec[1] ++ " -> " ++ spec[0] ++ " body", raw, body);

            // Protect: reproduce the vector's own bytes. The MLSMessage
            // header length is derived, not assumed, by re-encoding the
            // bare PublicMessage this message decoded to.
            const bare = try pm.encodeAlloc(alloc);
            defer alloc.free(bare);
            try testing.expect(std.mem.endsWith(u8, vec, bare));
            const header_len = vec.len - bare.len;

            const protected = try framing.protectPublic(S, alloc, .{
                .signature_key_pair = key_pair,
                .membership_key = membership_key,
                .group_context = gc_bytes,
                .content = pm.content,
                .confirmation_tag = pm.auth.confirmation_tag,
            });
            defer alloc.free(protected);
            try expectStage("protectPublic(" ++ spec[0] ++ ")", vec[header_len..], protected);
            public_checked += 1;
        }

        // ── §6: application content may not be sent as a PublicMessage ──
        {
            const app = try hexDecode(arena, obj.get("application").?.string);
            try testing.expectError(error.ApplicationContentMustBeEncrypted, framing.protectPublic(S, alloc, .{
                .signature_key_pair = key_pair,
                .membership_key = membership_key,
                .group_context = gc_bytes,
                .content = .{
                    .group_id = group_id,
                    .epoch = gc.epoch,
                    .sender = .{ .member = vector_sender_leaf },
                    .body = .{ .application = app },
                },
            }));
        }

        // ── §6.3: PrivateMessage, all three content types ──
        inline for (.{
            .{ "proposal", "proposal_priv" },
            .{ "commit", "commit_priv" },
            .{ "application", "application_priv" },
        }) |spec| {
            const raw = try hexDecode(arena, obj.get(spec[0]).?.string);
            const vec = try hexDecode(arena, obj.get(spec[1]).?.string);

            var r = codec.Reader.init(vec);
            const msg = try framing.MLSMessage.decode(alloc, &r);
            defer msg.deinit(alloc);
            try testing.expect(r.atEnd());
            const pmsg = msg.private_message;

            // §6.3.2 first: the sender data is what names the key.
            const sd = framing.decryptSenderData(S, alloc, pmsg, sender_data_secret) catch |err| {
                std.debug.print("framing KAT: '" ++ spec[1] ++ " sender data (§6.3.2)' failed: {s}\n", .{@errorName(err)});
                return err;
            };
            try testing.expectEqual(vector_sender_leaf, sd.leaf_index);

            const kind: secrettree.RatchetKind = if (pmsg.content_type == .application) .application else .handshake;
            const kn = try ratchetKeyNonce(encryption_secret, sd.leaf_index, kind, sd.generation);

            const plaintext = framing.decryptContent(S, alloc, pmsg, kn, sd.reuse_guard) catch |err| {
                std.debug.print("framing KAT: '" ++ spec[1] ++ " content AEAD (§6.3.1)' failed: {s}\n", .{@errorName(err)});
                return err;
            };
            defer alloc.free(plaintext);
            const ac = try framing.parsePrivateContent(alloc, pmsg, plaintext, sd.leaf_index);
            defer ac.deinit(alloc);

            const body = try encodeBodyAlloc(alloc, ac.content.body);
            defer alloc.free(body);
            try expectStage(spec[1] ++ " -> " ++ spec[0] ++ " body", raw, body);
            try expectStageOk(spec[1] ++ " signature (§6.1)", framing.verifyFramedContent(S, alloc, signature_pub, ac, gc_bytes));

            // Protect: every non-deterministic input (reuse guard,
            // generation, padding length) is recovered from the vector, so
            // the output must match it byte-for-byte. The padding length is
            // what the plaintext has left over after body and auth.
            const padding_len = plaintext.len -
                (ac.content.body.encodedLen() + ac.auth.encodedLenFor(pmsg.content_type));

            const bare = try pmsg.encodeAlloc(alloc);
            defer alloc.free(bare);
            try testing.expect(std.mem.endsWith(u8, vec, bare));
            const header_len = vec.len - bare.len;

            const protected = try framing.protectPrivate(S, alloc, .{
                .signature_key_pair = key_pair,
                .group_context = gc_bytes,
                .content = ac.content,
                .confirmation_tag = ac.auth.confirmation_tag,
                .key_nonce = kn,
                .generation = sd.generation,
                .reuse_guard = sd.reuse_guard,
                .sender_data_secret = sender_data_secret,
                .padding_len = padding_len,
            });
            defer alloc.free(protected);
            try expectStage("protectPrivate(" ++ spec[0] ++ ")", vec[header_len..], protected);
            private_checked += 1;
        }
    }

    try testing.expect(found_suite_1);
    try testing.expectEqual(@as(usize, 2), public_checked);
    try testing.expectEqual(@as(usize, 3), private_checked);
    // Suites 0x0002-0x0007 each contribute one entry.
    try testing.expectEqual(@as(usize, 6), skipped_other_suites);
}

test "message-protection.json: a tampered ciphertext byte fails the content AEAD, not silently" {
    // Proves the §6.3.1 AEAD is actually authenticating the payload rather
    // than the harness accepting whatever decrypts to something parseable.
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, message_protection_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();
    const alloc = testing.allocator;

    for (parsed.value.array.items) |entry| {
        const obj = entry.object;
        if (asI64(obj.get("cipher_suite").?) != @as(i64, @intFromEnum(S.id))) continue;

        const vec = try hexDecode(arena, obj.get("application_priv").?.string);
        const encryption_secret = try hexSecret(obj.get("encryption_secret").?.string);
        const sender_data_secret = try hexSecret(obj.get("sender_data_secret").?.string);

        var r = codec.Reader.init(vec);
        const msg = try framing.MLSMessage.decode(alloc, &r);
        defer msg.deinit(alloc);
        const pmsg = msg.private_message;
        const sd = try framing.decryptSenderData(S, alloc, pmsg, sender_data_secret);
        const kn = try ratchetKeyNonce(encryption_secret, sd.leaf_index, .application, sd.generation);

        // Flip one bit in the middle of the ciphertext.
        const tampered = try alloc.dupe(u8, pmsg.ciphertext);
        defer alloc.free(tampered);
        tampered[tampered.len / 2] ^= 0x01;
        var bad = pmsg;
        bad.ciphertext = tampered;

        try testing.expectError(
            error.DecryptionFailed,
            framing.decryptContent(S, alloc, bad, kn, sd.reuse_guard),
        );
        return;
    }
    return error.SkipZigTest;
}

test "transcript-hashes.json: RFC 9420 §8.2's two hashes for suite 0x0001, byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, transcript_hashes_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();
    const alloc = testing.allocator;

    var found_suite_1 = false;
    var skipped_other_suites: usize = 0;

    for (parsed.value.array.items) |entry| {
        const obj = entry.object;
        if (asI64(obj.get("cipher_suite").?) != @as(i64, @intFromEnum(S.id))) {
            skipped_other_suites += 1;
            continue;
        }
        found_suite_1 = true;

        const ac_bytes = try hexDecode(arena, obj.get("authenticated_content").?.string);
        var r = codec.Reader.init(ac_bytes);
        const ac = try framing.AuthenticatedContent.decode(alloc, &r);
        defer ac.deinit(alloc);
        try testing.expect(r.atEnd());
        // §8.2 hashes Commits, so the vector must be one.
        try testing.expectEqual(framing.ContentType.commit, ac.content.contentType());

        // The `AuthenticatedContent` encoding itself is load-bearing here
        // (it is what the confirmed hash is computed over), so pin it.
        const re = try ac.encodeAlloc(alloc);
        defer alloc.free(re);
        try expectStage("AuthenticatedContent re-encode", ac_bytes, re);

        const interim_before = try hexDecode(arena, obj.get("interim_transcript_hash_before").?.string);
        const hashes = try transcript.advance(S, alloc, interim_before, ac);
        try expectStage(
            "confirmed_transcript_hash_after",
            try hexDecode(arena, obj.get("confirmed_transcript_hash_after").?.string),
            &hashes.confirmed,
        );
        try expectStage(
            "interim_transcript_hash_after",
            try hexDecode(arena, obj.get("interim_transcript_hash_after").?.string),
            &hashes.interim,
        );

        // Upstream's first verification step: the Commit's own
        // `confirmation_tag` must be a valid MAC over the confirmed hash it
        // just produced — the §6.1/§8.2 circularity this module resolves by
        // stopping `ConfirmedTranscriptHashInput` at the signature.
        const confirmation_key = try hexSecret(obj.get("confirmation_key").?.string);
        try expectStageOk("confirmation_tag over confirmed_transcript_hash_after", keyschedule.verifyConfirmationTag(
            S,
            confirmation_key,
            &hashes.confirmed,
            ac.auth.confirmation_tag.?,
        ));
    }

    try testing.expect(found_suite_1);
    try testing.expectEqual(@as(usize, 6), skipped_other_suites);
}

test "transcript-hashes.json: the confirmation_tag does NOT verify against the hash it is not defined over" {
    // The confirmed hash and the interim hash are one hash step apart, and
    // both are 32 bytes — so a §8.2 implementation that returned the wrong
    // one would still typecheck and still look plausible. This is the check
    // that separates them.
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, transcript_hashes_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();
    const alloc = testing.allocator;

    for (parsed.value.array.items) |entry| {
        const obj = entry.object;
        if (asI64(obj.get("cipher_suite").?) != @as(i64, @intFromEnum(S.id))) continue;

        const ac_bytes = try hexDecode(arena, obj.get("authenticated_content").?.string);
        var r = codec.Reader.init(ac_bytes);
        const ac = try framing.AuthenticatedContent.decode(alloc, &r);
        defer ac.deinit(alloc);

        const interim_before = try hexDecode(arena, obj.get("interim_transcript_hash_before").?.string);
        const hashes = try transcript.advance(S, alloc, interim_before, ac);
        const confirmation_key = try hexSecret(obj.get("confirmation_key").?.string);

        try testing.expectError(error.MacMismatch, keyschedule.verifyConfirmationTag(
            S,
            confirmation_key,
            &hashes.interim,
            ac.auth.confirmation_tag.?,
        ));
        try testing.expectError(error.MacMismatch, keyschedule.verifyConfirmationTag(
            S,
            confirmation_key,
            interim_before,
            ac.auth.confirmation_tag.?,
        ));
        return;
    }
    return error.SkipZigTest;
}
