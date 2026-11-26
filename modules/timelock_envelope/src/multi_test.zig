// SPDX-License-Identifier: MIT

//! Tests of the version-3 multi-recipient envelope (`multi.zig`): every
//! recipient opens, a stranger does not, the time lock still gates every
//! slot, the slots are bound to the envelope, and the recipient bounds hold.

const std = @import("std");
const hqc = @import("hqc");
const envelope = @import("envelope.zig");
const multi = @import("multi.zig");
const sec = @import("security_test.zig");

const testing = std.testing;
const Env = envelope.Envelope128;
const Kem = hqc.Hqc128;
const M = multi.Multi(Kem);

const plaintext = "three readers, one round";

fn fixedMultiRandomness(coins: [][Kem.coins_bytes]u8) Env.MultiRandomness {
    for (coins, 0..) |*c, i| c.* = @splat(@intCast(0x40 + i));
    return .{
        .s_time = @splat(0x11),
        .tlock_sigma = @splat(0x22),
        .file_key = @splat(0x33),
        .kem_coins = coins,
    };
}

fn sealThree(kps: *const [3]Kem.KeyPair) ![]u8 {
    var coins: [3][Kem.coins_bytes]u8 = undefined;
    const rnd = fixedMultiRandomness(&coins);
    const eks = [_]*const Kem.EncapsKey{ &kps[0].ek, &kps[1].ek, &kps[2].ek };
    return Env.sealMultiWithRandomness(testing.allocator, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, &rnd, .{});
}

test "multi: every recipient opens, a stranger and a premature signature do not" {
    const kps = [3]Kem.KeyPair{ sec.recipientKeypair(0x01), sec.recipientKeypair(0x02), sec.recipientKeypair(0x03) };
    const env = try sealThree(&kps);
    defer testing.allocator.free(env);
    try testing.expectEqual(Env.multiSealedLen(3, plaintext.len), env.len);

    for (&kps) |*kp| {
        const pt = try Env.openMulti(testing.allocator, env, &kp.dk, sec.round1000Signature(), .{});
        defer testing.allocator.free(pt);
        try testing.expectEqualSlices(u8, plaintext, pt);
    }
    const stranger = sec.recipientKeypair(0x09);
    try testing.expectError(error.AuthFailed, Env.openMulti(testing.allocator, env, &stranger.dk, sec.round1000Signature(), .{}));
    // The time lock gates every slot: a recipient's key alone does nothing.
    try testing.expectError(error.TimeGateClosed, Env.openMulti(testing.allocator, env, &kps[1].dk, sec.wrongSignature(), .{}));

    const h = try Env.peekHeader(env);
    try testing.expectEqual(multi.multi_version, h.version);
    try testing.expectEqual(sec.seal_round, h.round);
}

test "multi: the content binds every slot; a flipped byte anywhere is refused" {
    const kps = [3]Kem.KeyPair{ sec.recipientKeypair(0x01), sec.recipientKeypair(0x02), sec.recipientKeypair(0x03) };
    const env = try sealThree(&kps);
    defer testing.allocator.free(env);
    // flags, the time lock, slot 0's HQC ct, slot 2's wrapped key, its tag, the
    // content tag and the ciphertext.
    const slot0 = M.prefix_bytes + M.time_lock_bytes;
    const positions = [_]usize{
        6,
        M.prefix_bytes + 50,
        slot0 + 10,
        slot0 + 2 * M.slot_bytes + Kem.ct_bytes + 3,
        slot0 + 3 * M.slot_bytes - 1,
        slot0 + 3 * M.slot_bytes + 2,
        env.len - 1,
    };
    for (positions) |pos| {
        const bad = try testing.allocator.dupe(u8, env);
        defer testing.allocator.free(bad);
        bad[pos] ^= 0x01;
        // Recipient 1's own slot is intact in every case except the time
        // lock flip; whichever check catches it, nothing opens.
        if (Env.openMulti(testing.allocator, bad, &kps[1].dk, sec.round1000Signature(), .{})) |pt| {
            testing.allocator.free(pt);
            return error.TamperAccepted;
        } else |_| {}
    }
}

test "multi: recipient bounds and framing" {
    const kps = [3]Kem.KeyPair{ sec.recipientKeypair(0x01), sec.recipientKeypair(0x02), sec.recipientKeypair(0x03) };
    const eks = [_]*const Kem.EncapsKey{ &kps[0].ek, &kps[1].ek, &kps[2].ek };
    var coins: [3][Kem.coins_bytes]u8 = undefined;
    const rnd = fixedMultiRandomness(&coins);
    try testing.expectError(error.NoRecipients, Env.sealMultiWithRandomness(testing.allocator, plaintext, eks[0..0], sec.quicknetPubkey(), sec.seal_round, &rnd, .{}));
    try testing.expectError(error.TooManyRecipients, Env.sealMultiWithRandomness(testing.allocator, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, &rnd, .{ .max_recipients = 2 }));

    const env = try sealThree(&kps);
    defer testing.allocator.free(env);
    try testing.expectError(error.TooManyRecipients, Env.openMulti(testing.allocator, env, &kps[0].dk, sec.round1000Signature(), .{ .max_recipients = 2 }));
    try testing.expectError(error.LengthMismatch, Env.openMulti(testing.allocator, env[0 .. env.len - 1], &kps[0].dk, sec.round1000Signature(), .{}));
    try testing.expectError(error.Truncated, M.parse(env[0..10], .{}));
    // A version-3 buffer is not a version-1 one, and vice versa.
    try testing.expectError(error.UnsupportedVersion, Env.open(testing.allocator, env, &kps[0].dk, sec.round1000Signature()));
    const zero = try testing.allocator.dupe(u8, env);
    defer testing.allocator.free(zero);
    std.mem.writeInt(u16, zero[19..21], 0, .little);
    try testing.expectError(error.LengthMismatch, M.parse(zero, .{}));
}

test "multi: seal with io draws fresh randomness each call" {
    const kp = sec.recipientKeypair(0x05);
    const eks = [_]*const Kem.EncapsKey{&kp.ek};
    const a = try Env.sealMulti(testing.allocator, testing.io, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, .{});
    defer testing.allocator.free(a);
    const b = try Env.sealMulti(testing.allocator, testing.io, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, .{});
    defer testing.allocator.free(b);
    try testing.expect(!std.mem.eql(u8, a, b));
    const pt = try Env.openMulti(testing.allocator, a, &kp.dk, sec.round1000Signature(), .{});
    defer testing.allocator.free(pt);
    try testing.expectEqualSlices(u8, plaintext, pt);
}

// ── tests added by the 2026-11-25 whole-module mutation run ─────────────────

const Aead = @import("chachapoly").ChaCha20Poly1305;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// HKDF-SHA256(kdf_salt, ikm, info) -> 32-byte key, 12-byte nonce, as the
/// module's wire doc describes it (written out again, not shared with `multi.zig`).
fn kdf(ikm: []const u8, info: []const u8) struct { key: [32]u8, nonce: [envelope.nonce_bytes]u8 } {
    const prk = Hkdf.extract(envelope.kdf_salt, ikm);
    var okm: [32 + envelope.nonce_bytes]u8 = undefined;
    Hkdf.expand(&okm, info, prk);
    return .{ .key = okm[0..32].*, .nonce = okm[32..][0..envelope.nonce_bytes].* };
}

test "mutation 2026-11-25: multi: header, HQC slots, slot keys, file key and both AADs follow the documented derivation" {
    const kps = [2]Kem.KeyPair{ sec.recipientKeypair(0x01), sec.recipientKeypair(0x02) };
    var coins: [2][Kem.coins_bytes]u8 = undefined;
    const rnd = fixedMultiRandomness(&coins);
    const eks = [_]*const Kem.EncapsKey{ &kps[0].ek, &kps[1].ek };
    const env = try Env.sealMultiWithRandomness(testing.allocator, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, &rnd, .{});
    defer testing.allocator.free(env);

    try testing.expectEqualSlices(u8, &envelope.magic, env[0..4]);
    try testing.expectEqual(@as(u8, 3), env[4]);
    try testing.expectEqual(Env.suite_id, env[5]);
    try testing.expectEqual(@as(u8, 0), env[6]); // flags
    try testing.expectEqual(sec.seal_round, std.mem.readInt(u64, env[7..15], .little));
    try testing.expectEqual(@as(u32, plaintext.len), std.mem.readInt(u32, env[15..19], .little));
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, env[19..21], .little));

    const slot0 = M.prefix_bytes + M.time_lock_bytes;
    for (0..2) |i| {
        const slot = env[slot0 + i * M.slot_bytes ..][0..M.slot_bytes];
        // The slot's HQC ciphertext is the encapsulation to ITS recipient with ITS coins.
        var ct: Kem.Ciphertext = undefined;
        var ss: Kem.SharedSecret = undefined;
        Kem.encaps(&ct, &ss, &kps[i].ek, &coins[i]);
        try testing.expectEqualSlices(u8, &ct, slot[0..Kem.ct_bytes]);
        // k_i, n_i = HKDF(s_time || ss_i, "TLE1-slot-key" || 3 || suite || round_be || i_be16)
        var ikm: [rnd.s_time.len + @sizeOf(Kem.SharedSecret)]u8 = undefined;
        @memcpy(ikm[0..rnd.s_time.len], &rnd.s_time);
        @memcpy(ikm[rnd.s_time.len..], std.mem.asBytes(&ss));
        var info: [13 + 1 + 1 + 8 + 2]u8 = undefined;
        @memcpy(info[0..13], "TLE1-slot-key");
        info[13] = 3;
        info[14] = Env.suite_id;
        std.mem.writeInt(u64, info[15..23], sec.seal_round, .big);
        std.mem.writeInt(u16, info[23..25], @intCast(i), .big);
        const k = kdf(&ikm, &info);
        // aad = SHA-256(prefix || time lock || this slot's HQC ciphertext)
        var h = Sha256.init(.{});
        h.update(env[0..slot0]);
        h.update(slot[0..Kem.ct_bytes]);
        var aad: [32]u8 = undefined;
        h.final(&aad);
        var fk: [32]u8 = undefined;
        try Aead.decrypt(&fk, slot[Kem.ct_bytes..][0..32], slot[Kem.ct_bytes + 32 ..][0..envelope.tag_bytes].*, &aad, k.nonce, k.key);
        try testing.expectEqualSlices(u8, &rnd.file_key, &fk);
    }

    // content: (K, N) = HKDF(F, "TLE1-file-key" || 3 || suite || round_be); aad = everything before the tag.
    var info: [13 + 1 + 1 + 8]u8 = undefined;
    @memcpy(info[0..13], "TLE1-file-key");
    info[13] = 3;
    info[14] = Env.suite_id;
    std.mem.writeInt(u64, info[15..23], sec.seal_round, .big);
    const ck = kdf(&rnd.file_key, &info);
    const off = slot0 + 2 * M.slot_bytes;
    var pt: [plaintext.len]u8 = undefined;
    try Aead.decrypt(&pt, env[off + envelope.tag_bytes ..][0..plaintext.len], env[off..][0..envelope.tag_bytes].*, env[0..off], ck.nonce, ck.key);
    try testing.expectEqualSlices(u8, plaintext, &pt);
}

test "mutation 2026-11-25: multi: framing checks each refuse with their own error" {
    const kps = [3]Kem.KeyPair{ sec.recipientKeypair(0x01), sec.recipientKeypair(0x02), sec.recipientKeypair(0x03) };
    const env = try sealThree(&kps);
    defer testing.allocator.free(env);
    // Exactly the fixed prefix: long enough to be framed, not the right length.
    try testing.expectError(error.LengthMismatch, M.parse(env[0..M.prefix_bytes], .{}));
    try testing.expectError(error.Truncated, M.parse(env[0 .. M.prefix_bytes - 1], .{}));
    const bad = try testing.allocator.dupe(u8, env);
    defer testing.allocator.free(bad);
    bad[0] ^= 1;
    try testing.expectError(error.BadMagic, M.parse(bad, .{}));
    bad[0] ^= 1;
    bad[4] = 1;
    try testing.expectError(error.UnsupportedVersion, M.parse(bad, .{}));
    bad[4] = 3;
    bad[5] ^= 1;
    try testing.expectError(error.SuiteMismatch, M.parse(bad, .{}));
    bad[5] ^= 1;
    // A count of 0 on a buffer whose length matches it is still refused.
    const empty = try testing.allocator.alloc(u8, M.sealedLen(0, 0));
    defer testing.allocator.free(empty);
    @memcpy(empty[0..M.prefix_bytes], env[0..M.prefix_bytes]);
    std.mem.writeInt(u32, empty[15..19], 0, .little);
    std.mem.writeInt(u16, empty[19..21], 0, .little);
    try testing.expectError(error.LengthMismatch, M.parse(empty, .{}));
    // A count equal to the limit is accepted.
    _ = try M.parse(env, .{ .max_recipients = 3 });
    try testing.expectError(error.TooManyRecipients, M.parse(env, .{ .max_recipients = 2 }));
    // An undecodable time lock is its own error; a damaged content tag is AuthFailed (not the time gate).
    bad[M.prefix_bytes] &= 0x7f;
    try testing.expectError(error.MalformedTimeLock, Env.openMulti(testing.allocator, bad, &kps[0].dk, sec.round1000Signature(), .{}));
    bad[M.prefix_bytes] = env[M.prefix_bytes];
    bad[bad.len - 1] ^= 1;
    try testing.expectError(error.AuthFailed, Env.openMulti(testing.allocator, bad, &kps[1].dk, sec.round1000Signature(), .{}));
}

test "mutation 2026-11-25: multi: recipient limits are inclusive, on both entry points" {
    const kps = [3]Kem.KeyPair{ sec.recipientKeypair(0x01), sec.recipientKeypair(0x02), sec.recipientKeypair(0x03) };
    const eks = [_]*const Kem.EncapsKey{ &kps[0].ek, &kps[1].ek, &kps[2].ek };
    var coins: [3][Kem.coins_bytes]u8 = undefined;
    const rnd = fixedMultiRandomness(&coins);
    const at_limit = try Env.sealMultiWithRandomness(testing.allocator, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, &rnd, .{ .max_recipients = 3 });
    testing.allocator.free(at_limit);
    // The io entry point: exactly at the limit seals, one over refuses, none is NoRecipients.
    const two = try Env.sealMulti(testing.allocator, testing.io, plaintext, eks[0..2], sec.quicknetPubkey(), sec.seal_round, .{ .max_recipients = 2 });
    testing.allocator.free(two);
    try testing.expectError(error.TooManyRecipients, Env.sealMulti(testing.allocator, testing.io, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, .{ .max_recipients = 2 }));
    try testing.expectError(error.NoRecipients, Env.sealMulti(testing.allocator, testing.io, plaintext, eks[0..0], sec.quicknetPubkey(), sec.seal_round, .{}));
}

test "mutation 2026-11-25: multi: a plaintext over the u32 length field is refused, exactly 2^32 - 1 reaches the allocation" {
    const kp = sec.recipientKeypair(0x0F);
    const eks = [_]*const Kem.EncapsKey{&kp.ek};
    var coins: [1][Kem.coins_bytes]u8 = undefined;
    const rnd = fixedMultiRandomness(&coins);
    const byte: [1]u8 = .{0};
    const edge = @as([*]const u8, &byte)[0..std.math.maxInt(u32)];
    try testing.expectError(error.OutOfMemory, Env.sealMultiWithRandomness(testing.failing_allocator, edge, &eks, sec.quicknetPubkey(), sec.seal_round, &rnd, .{}));
    const huge = @as([*]const u8, &byte)[0 .. @as(usize, std.math.maxInt(u32)) + 1];
    try testing.expectError(error.PlaintextTooLarge, Env.sealMultiWithRandomness(testing.failing_allocator, huge, &eks, sec.quicknetPubkey(), sec.seal_round, &rnd, .{}));
}

var det_counter: usize = 0;
var det_vtable: std.Io.VTable = undefined;
fn detByte(k: usize) u8 {
    return @truncate(k *% 131 +% 7);
}
fn detRandomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    for (buffer) |*b| {
        b.* = detByte(det_counter);
        det_counter += 1;
    }
}
fn detSwapCancelProtection(_: ?*anyopaque, _: std.Io.CancelProtection) std.Io.CancelProtection {
    return .unblocked;
}
/// An `Io` whose entropy is a known byte stream (copy of std's failing table
/// with two slots replaced, so `entropy.fill` takes its `randomSecure` path).
fn detIo() std.Io {
    det_vtable = std.Io.failing.vtable.*;
    det_vtable.randomSecure = detRandomSecure;
    det_vtable.swapCancelProtection = detSwapCancelProtection;
    det_counter = 0;
    return .{ .userdata = null, .vtable = &det_vtable };
}

test "mutation 2026-11-25: multi: sealMulti draws s_time, sigma, file key and one coin set per recipient, in that order" {
    const kps = [2]Kem.KeyPair{ sec.recipientKeypair(0x01), sec.recipientKeypair(0x02) };
    const eks = [_]*const Kem.EncapsKey{ &kps[0].ek, &kps[1].ek };
    // The same bytes by hand: stream positions 0.., in draw order.
    var pos: usize = 0;
    var coins: [2][Kem.coins_bytes]u8 = undefined;
    var rnd: Env.MultiRandomness = .{ .s_time = undefined, .tlock_sigma = undefined, .file_key = undefined, .kem_coins = &coins };
    for (&rnd.s_time) |*b| {
        b.* = detByte(pos);
        pos += 1;
    }
    for (&rnd.tlock_sigma) |*b| {
        b.* = detByte(pos);
        pos += 1;
    }
    for (&rnd.file_key) |*b| {
        b.* = detByte(pos);
        pos += 1;
    }
    for (&coins) |*c| for (c) |*b| {
        b.* = detByte(pos);
        pos += 1;
    };
    const want = try Env.sealMultiWithRandomness(testing.allocator, plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, &rnd, .{});
    defer testing.allocator.free(want);
    const got = try Env.sealMulti(testing.allocator, detIo(), plaintext, &eks, sec.quicknetPubkey(), sec.seal_round, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, want, got);
}
