// SPDX-License-Identifier: MIT

//! What a consumer does with `bolt8`: run a full `Noise_XK` handshake
//! between an initiator and a responder in memory (no socket — a real
//! caller would relay `act1`/`act2`/`act3`'s bytes over a TCP connection,
//! see BOLT#8's own "Lightning Message Specification"), then exchange one
//! post-handshake Lightning message over the derived transport keys.
//!
//! Both sides use `.seeded_for_test` ephemerals here — explicitly the
//! non-production arm of `Ephemeral` (see `handshake.zig`'s doc comment):
//! this file has no entropy source to draw a real ephemeral from, and the
//! module's own module doc warns that using this arm in production is a
//! forward-secrecy failure, not a shortcut. A real node passes `.csprng`
//! seeded from the OS's CSPRNG instead — `genAct1WithEphemeral`/
//! `genAct2WithEphemeral`, the module's exact-vector KAT hooks, are NOT
//! reachable here: they `@compileError` outside a `zig test` build (see
//! `handshake.zig`'s `assertTestOnly`), so this example — a normal
//! `zig build-exe`, not a test binary — could not use them even to be lazy.
//!
//! Built against the PUBLISHED module (`@import("bolt8")`) plus its
//! declared deps `noise`/`k256` only — no `test_deps`, no socket.

const std = @import("std");
const bolt8 = @import("bolt8");

pub fn main() !void {
    // Fixed seeds stand in for "a real CSPRNG" so this example needs no
    // entropy syscall and reproduces the same run every time — see the
    // module doc comment above for why this is explicitly NOT the
    // production arm of `Ephemeral`.
    const init_ls = try bolt8.Secp256k1DH.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const resp_ls = try bolt8.Secp256k1DH.KeyPair.generateDeterministic([_]u8{0x21} ** 32);

    var init_rng = std.Random.DefaultPrng.init(0xC0FFEE);
    var resp_rng = std.Random.DefaultPrng.init(0xDECAFBAD);

    // The initiator must know the responder's static public key in
    // advance — BOLT#8 is `Noise_XK`, so it is never sent on the wire.
    var initiator = bolt8.Initiator.init(init_ls, resp_ls.public_key);
    var responder = bolt8.Responder.init(resp_ls);

    // Act One: initiator -> responder.
    const a1 = try initiator.genAct1(.{ .seeded_for_test = init_rng.random() });
    try responder.readAct1(a1);
    std.debug.print("act1 sent: {d} bytes\n", .{a1.toBytes().len});

    // Act Two: responder -> initiator.
    const a2 = try responder.genAct2(.{ .seeded_for_test = resp_rng.random() });
    try initiator.readAct2(a2);
    std.debug.print("act2 sent: {d} bytes\n", .{a2.toBytes().len});

    // Act Three: initiator -> responder. Both sides now hold the transport
    // keys; a real caller would tear down the `Initiator`/`Responder` here.
    const a3 = try initiator.genAct3();
    const rresult = try responder.readAct3(a3.msg);
    std.debug.print("act3 sent: {d} bytes\n", .{a3.msg.toBytes().len});
    std.debug.print("handshake hash matches on both sides: {}\n", .{std.mem.eql(u8, &a3.result.handshake_hash, &rresult.handshake_hash)});

    // ── post-handshake transport ────────────────────────────────────────
    var itx = bolt8.Transport.init(a3.result);
    var rtx = bolt8.Transport.init(rresult);

    const plaintext = "0100"; // a stand-in for a real Lightning message's 2-byte type + body
    var wire: [bolt8.transport.length_frame_len + plaintext.len + 16]u8 = undefined;
    try itx.sendMessage(plaintext, &wire);

    const length = try rtx.recvLength(wire[0..bolt8.transport.length_frame_len]);
    var out: [plaintext.len]u8 = undefined;
    try rtx.recvMessage(wire[bolt8.transport.length_frame_len..], out[0..length]);
    std.debug.print("responder decrypted: \"{s}\"\n", .{out[0..length]});

    // A wrong-length declaration or a flipped ciphertext byte must fail
    // closed — BOLT#8: "the connection is to be immediately terminated" on
    // any AEAD tag failure, never a best-effort decode.
    var tampered = wire;
    tampered[tampered.len - 1] ^= 0xff;
    var rtx2 = bolt8.Transport.init(rresult);
    const length2 = try rtx2.recvLength(tampered[0..bolt8.transport.length_frame_len]);
    var out2: [plaintext.len]u8 = undefined;
    rtx2.recvMessage(tampered[bolt8.transport.length_frame_len..], out2[0..length2]) catch |err| switch (err) {
        error.DecryptionFailed => {
            std.debug.print("tampered message rejected: DecryptionFailed\n", .{});
            return;
        },
        else => return err,
    };
    return error.TamperNotDetected;
}
