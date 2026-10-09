// SPDX-License-Identifier: MIT

//! What a protocol implementor does with `noise`: resolve a protocol name
//! (`Noise_XXpsk3_25519_ChaChaPoly_SHA256`), open both sides with the
//! checked `init`, drive the handshake (mutual authentication, static keys
//! revealed over the wire, a pre-shared key mixed in at the end) between an
//! initiator and a responder to
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

    // The protocol is named the way peers agree on it; the name resolves to
    // the pattern (XX, a PSK mixed in at the end of message 3) and must name
    // the suite this program binds.
    var storage: noise.PatternStorage = .{};
    const proto = try noise.parseProtocolName(&storage, "Noise_XXpsk3_25519_ChaChaPoly_SHA256");
    if (!Suite.matches(proto)) return error.WrongSuite;
    const psk = [_][32]u8{[_]u8{0x33} ** 32};

    // XX: neither side knows the other's static key in advance (no `rs`);
    // both reveal their static key DURING the handshake. `init` checks the
    // pattern against the keys each side holds before anything runs ...
    // The state is initialized in place and the keys travel by pointer: no copy
    // of a private key is left behind in a dead stack frame.
    var initiator: Suite.HandshakeState = .{};
    var responder: Suite.HandshakeState = .{};
    try initiator.init(proto.pattern, true, "", &.{ .s = &init_static, .psks = &psk });
    try responder.init(proto.pattern, false, "", &.{ .s = &resp_static, .psks = &psk });
    // ... and refuses a session the pattern cannot run, here one without the PSK.
    var scratch: Suite.HandshakeState = .{};
    if (scratch.init(proto.pattern, true, "", &.{ .s = &init_static })) |_| {
        return error.ExpectedRefusal;
    } else |err| std.debug.print("{s} without its PSK: {t}\n", .{ proto.pattern.name, err });

    var wire: [256]u8 = undefined;

    // Message 1: initiator -> responder (-> e).
    // `transport` is written only by the call that completes the pattern.
    var init_transport: [2]Suite.CipherState = undefined;
    var resp_transport: [2]Suite.CipherState = undefined;
    var step = try initiator.writeMessage(init_rng.random(), "", &wire, &init_transport);
    _ = try responder.readMessage(wire[0..step.len], &wire, &resp_transport);
    std.debug.print("message 1: {d} bytes\n", .{step.len});

    // Message 2: responder -> initiator (<- e, ee, s, es).
    step = try responder.writeMessage(resp_rng.random(), "", &wire, &resp_transport);
    _ = try initiator.readMessage(wire[0..step.len], &wire, &init_transport);
    std.debug.print("message 2: {d} bytes\n", .{step.len});

    // Message 3: initiator -> responder (-> s, se). This one completes the
    // pattern, so both transport pairs are filled in (`Step.complete`).
    step = try initiator.writeMessage(init_rng.random(), "", &wire, &init_transport);
    const resp_step = try responder.readMessage(wire[0..step.len], &wire, &resp_transport);
    if (!step.complete or !resp_step.complete) return error.HandshakeNotComplete;
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
