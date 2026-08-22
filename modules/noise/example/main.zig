// SPDX-License-Identifier: MIT

//! What a protocol implementor does with `noise`: drive a full `Noise_XX`
//! handshake (mutual authentication, static keys revealed over the wire
//! rather than known in advance) between an initiator and a responder to
//! completion, then use the derived transport `CipherState` pair to
//! exchange one application message — and show that a tampered ciphertext
//! fails closed by name rather than silently decoding garbage.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `noise` (or its declared dep `chachapoly`) does not
//! export.

const std = @import("std");
const noise = @import("noise");

const Suite = noise.DefaultSuite;

pub fn main() !void {
    // Fixed seeds keep this example reproducible; a real caller draws these
    // from a CSPRNG (e.g. `std.crypto.dh.X25519.KeyPair.generate(io)`).
    const init_static = try Suite.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const resp_static = try Suite.KeyPair.generateDeterministic([_]u8{0x22} ** 32);
    var init_rng = std.Random.DefaultPrng.init(0xC0FFEE);
    var resp_rng = std.Random.DefaultPrng.init(0xDECAFBAD);

    var initiator: Suite.HandshakeState = undefined;
    var responder: Suite.HandshakeState = undefined;
    // XX: neither side knows the other's static key in advance (both `rs`
    // are null); both reveal their static key DURING the handshake.
    initiator.initialize(noise.patterns.XX, true, "", init_static, null, null, null, &.{});
    responder.initialize(noise.patterns.XX, false, "", resp_static, null, null, null, &.{});

    var wire: [256]u8 = undefined;

    // Message 1: initiator -> responder (-> e).
    var step = try initiator.writeMessage(init_rng.random(), "", &wire);
    _ = try responder.readMessage(wire[0..step.len], &wire);
    std.debug.print("message 1: {d} bytes\n", .{step.len});

    // Message 2: responder -> initiator (<- e, ee, s, es).
    step = try responder.writeMessage(resp_rng.random(), "", &wire);
    _ = try initiator.readMessage(wire[0..step.len], &wire);
    std.debug.print("message 2: {d} bytes\n", .{step.len});

    // Message 3: initiator -> responder (-> s, se). This one completes the
    // pattern, so both `Step.transport` fields are populated.
    step = try initiator.writeMessage(init_rng.random(), "", &wire);
    const init_transport = step.transport.?;
    const resp_step = try responder.readMessage(wire[0..step.len], &wire);
    const resp_transport = resp_step.transport.?;
    std.debug.print("message 3: {d} bytes\n", .{step.len});

    std.debug.print("handshake hash matches on both sides: {}\n", .{
        std.mem.eql(
            u8,
            &initiator.symmetric_state.getHandshakeHash(),
            &responder.symmetric_state.getHandshakeHash(),
        ),
    });

    // ── post-handshake transport ────────────────────────────────────────
    // [0] = initiator -> responder direction; both sides get the same pair.
    var send = init_transport[0];
    var recv = resp_transport[0];

    const plaintext = "order-42: BUY 100 ACME @ 210.50";
    var ct: [plaintext.len + Suite.TAGLEN]u8 = undefined;
    try send.encryptWithAd(&.{}, plaintext, &ct);

    var pt: [plaintext.len]u8 = undefined;
    try recv.decryptWithAd(&.{}, &ct, &pt);
    std.debug.print("responder decrypted: \"{s}\"\n", .{pt});

    // A flipped ciphertext byte must fail closed, not decode to garbage.
    var tampered = ct;
    tampered[tampered.len - 1] ^= 0xff;
    var recv2 = resp_transport[0];
    recv2.decryptWithAd(&.{}, &tampered, &pt) catch |err| switch (err) {
        error.DecryptionFailed => {
            std.debug.print("tampered ciphertext correctly rejected (DecryptionFailed)\n", .{});
            return;
        },
        else => return err,
    };
    return error.TamperNotDetected;
}
