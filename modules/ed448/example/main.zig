// SPDX-License-Identifier: MIT

//! What a signer does with `ed448`: generate an Ed448 key pair (the
//! ~224-bit security level curve, one step up from Ed25519), sign a
//! message, verify it, then show the two ways verification fails by
//! name — a tampered message and a context string over the RFC 8032
//! limit — rather than crashing or silently accepting.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `ed448` does not export.

const std = @import("std");
const ed448 = @import("ed448");

pub fn main() !void {
    // No allocator needed: KeyPair.generate/sign/verify are all pure over
    // fixed-size arrays. Entropy still needs an `std.Io` instance.
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var kp = ed448.ed448.KeyPair.generate(io);
    defer kp.deinit();

    const message = "deploy release v3 to the edge fleet";
    const ctx = "example-protocol-v1";

    const sig = try ed448.ed448.sign(kp, message, ctx);
    try ed448.ed448.verify(sig, message, ctx, kp.public_key);
    std.debug.print("signature verified over {d} bytes\n", .{message.len});

    // A tampered message must fail verification by name, not just return
    // false or panic — a caller building an accept/reject gate depends on
    // this being a nameable error.
    const tampered = "deploy release v3 to the EDGE fleet";
    ed448.ed448.verify(sig, tampered, ctx, kp.public_key) catch |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("tampered message correctly rejected\n", .{}),
        else => return err,
    };

    // RFC 8032's context string is capped at 255 bytes; sign() has to
    // reject an oversized one rather than truncate it silently (silent
    // truncation would let two different contexts collide).
    var huge_ctx: [ed448.ed448.max_context_length + 1]u8 = @splat('x');
    if (ed448.ed448.sign(kp, message, &huge_ctx)) |_| {
        std.debug.print("unexpectedly signed with an oversized context\n", .{});
    } else |err| switch (err) {
        error.ContextTooLong => std.debug.print("oversized context correctly rejected (ContextTooLong)\n", .{}),
    }

    // X448 side: an ephemeral Diffie-Hellman exchange between two parties,
    // the Montgomery-form sibling of the same curve family.
    var alice = ed448.x448.KeyPair.generate(io);
    defer alice.deinit();
    var bob = ed448.x448.KeyPair.generate(io);
    defer bob.deinit();

    const alice_shared = try ed448.x448.scalarmult(alice.secret_key, bob.public_key);
    const bob_shared = try ed448.x448.scalarmult(bob.secret_key, alice.public_key);
    std.debug.print("X448 shared secret agrees: {}\n", .{std.mem.eql(u8, &alice_shared, &bob_shared)});
}
