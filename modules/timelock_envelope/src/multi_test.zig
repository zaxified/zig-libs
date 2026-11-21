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
