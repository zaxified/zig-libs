// SPDX-License-Identifier: MIT

//! What a group-messaging consumer does with `megolm`: a sender shares a
//! `SessionKey` with a room's members (Matrix's `m.room_key` event), each
//! member builds an `InboundGroupSession` from it, and messages the
//! sender encrypts afterwards decrypt for every member that got the key —
//! including one who joined mid-conversation, because the ratchet is a
//! one-way hash chain a member can fast-forward from any earlier state
//! (megolm.md; see `ratchet.zig`'s module doc comment for the fast-forward
//! algorithm).
//!
//! The sender's `OutboundSession` is built from `Ratchet.init` with a
//! fixed 128-byte state and `Ed25519.KeyPair.generateDeterministic`
//! instead of `OutboundSession.init(io)`, because `.init` draws its
//! ratchet and signing key from `entropy.fill` — a real `getrandom(2)`
//! syscall this file must not make (see rule 3). `Ratchet.init` and
//! `OutboundSession`'s public fields make this a legitimate, if unusual,
//! construction path — see this example's accompanying report for the
//! one place that path runs out.
//!
//! Built against the PUBLISHED module (`@import("megolm")`) plus its
//! declared deps `aescbc`/`entropy` — `entropy` is imported only because
//! `OutboundSession`'s type signature mentions `std.Io` transitively
//! through the module it's declared in, not because this file calls it.

const std = @import("std");
const megolm = @import("megolm");

const Ed25519 = std.crypto.sign.Ed25519;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Fixed ratchet state + deterministic signing key stand in for a real
    // sender's `OutboundSession.init(io)` draw — see module doc comment.
    const signing_key = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    var outbound: megolm.OutboundSession = .{
        .ratchet = megolm.Ratchet.init([_]u8{0x37} ** megolm.ratchet.ratchet_len, 0),
        .signing_key = signing_key,
    };
    defer outbound.deinit();

    // ── session setup: share the key with the room ────────────────────
    const shared_key = try outbound.sessionKey();
    var inbound = try megolm.InboundGroupSession.fromSessionKey(shared_key);
    defer inbound.deinit();
    std.debug.print("first_known_index: {d}\n", .{inbound.firstKnownIndex()});

    // ── message 0: sent before the late joiner below has the key ──────
    var msg0 = try outbound.encrypt(gpa, "welcome to the room");
    defer msg0.deinit(gpa);

    var got0 = try inbound.decrypt(gpa, &msg0);
    defer got0.deinit(gpa);
    std.debug.print("member decrypted index {d}: \"{s}\"\n", .{ got0.message_index, got0.plaintext });

    // ── message 1: sent to the room before the late joiner gets the key.
    var msg1 = try outbound.encrypt(gpa, "message the late joiner should NOT see");
    defer msg1.deinit(gpa);

    // The late joiner's session starts at whatever index the ratchet is
    // at when they're given the key (index 2, after two encrypts) — but
    // can still decrypt everything sent AFTER that point, fast-forwarding
    // from their own starting state without replaying key-by-key.
    const late_key = try outbound.sessionKey();
    var late_inbound = try megolm.InboundGroupSession.fromSessionKey(late_key);
    defer late_inbound.deinit();

    var msg2 = try outbound.encrypt(gpa, "message the late joiner CAN see");
    defer msg2.deinit(gpa);
    var got2 = try late_inbound.decrypt(gpa, &msg2);
    defer got2.deinit(gpa);
    std.debug.print("late joiner decrypted index {d}: \"{s}\"\n", .{ got2.message_index, got2.plaintext });

    // The one-way property: the late joiner cannot go BACKWARD to a
    // message from before their session started.
    if (late_inbound.decrypt(gpa, &msg1)) |early| {
        var e = early;
        e.deinit(gpa);
        return error.OldIndexNotRejected;
    } else |err| switch (err) {
        error.MessageIndexTooOld => std.debug.print("late joiner correctly cannot decrypt index 1: MessageIndexTooOld\n", .{}),
        else => return err,
    }

    // ── fail-closed: a tampered ciphertext fails the signature check
    // before the ratchet is even consulted (session.zig's module doc:
    // "an unauthenticated message shouldn't get to influence which
    // ratchet state gets fast-forwarded").
    var tampered = try outbound.encrypt(gpa, "trip the alarm");
    defer tampered.deinit(gpa);
    tampered.ciphertext[0] ^= 0xff;
    var tamper_target = try megolm.InboundGroupSession.fromSessionKey(late_key);
    defer tamper_target.deinit();
    if (tamper_target.decrypt(gpa, &tampered)) |bad| {
        var b = bad;
        b.deinit(gpa);
        return error.TamperNotDetected;
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("tampered message rejected: InvalidSignature\n", .{}),
        else => return err,
    }
}
