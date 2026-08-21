// SPDX-License-Identifier: MIT

//! What a client sealing a message to a recipient's long-term public key
//! does with `hpke`: run RFC 9180's base-mode `SetupBaseS`/`SetupBaseR` to
//! get a shared `Context` on both sides (not the single-shot `sealBase`
//! convenience — a real session sends more than one message), seal two
//! messages in sequence, open them on the receiving side, and pull a
//! matching exported secret out of both contexts (the RFC 9420/MLS
//! external-init use case this module's docs call out). Also shows a
//! tampered ciphertext failing to open by a nameable error.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const hpke = @import("hpke");

const Kem = hpke.X25519Kem;
const Aead = hpke.ChaCha20Poly1305;
const Nh = 32; // HKDF-SHA256 output width — dhkem_x25519_hkdf_sha256's KDF

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The recipient's long-term static keypair, published out of band
    // (a real deployment would load this from key storage, not mint it
    // fresh — generated here only so the example is self-contained).
    const recipient = Kem.generateKeyPair(io);

    const info = "example.org hpke session v1";

    // Sender side: SetupBaseS gives back both the encapsulated key (`enc`,
    // which travels alongside the ciphertext) and a multi-message Context.
    const sender_setup = try hpke.setupBaseS(Kem, Aead, Nh, recipient.public_key, io, info);
    var sender_ctx = sender_setup.context;

    // Receiver side: SetupBaseR recovers the identical Context from `enc`
    // and its own private key — no `Context` is ever sent on the wire.
    var receiver_ctx = try hpke.setupBaseR(Kem, Aead, Nh, sender_setup.enc, recipient, info);

    // Message 1.
    const msg1 = "order: BUY 100 XYZ @ market";
    var ct1: [msg1.len + Aead.tag_length]u8 = undefined;
    try sender_ctx.seal("", msg1, &ct1);
    var pt1: [msg1.len]u8 = undefined;
    try receiver_ctx.open("", &ct1, &pt1);
    std.debug.print("message 1: \"{s}\"\n", .{pt1});

    // Message 2 — the sequence number advances on both sides independently;
    // a real Context is meant for more than one Seal/Open.
    const msg2 = "order: SELL 40 XYZ @ market";
    var ct2: [msg2.len + Aead.tag_length]u8 = undefined;
    try sender_ctx.seal("", msg2, &ct2);
    var pt2: [msg2.len]u8 = undefined;
    try receiver_ctx.open("", &ct2, &pt2);
    std.debug.print("message 2: \"{s}\"\n", .{pt2});

    // A tampered ciphertext must fail to open by a nameable error, not
    // panic or silently produce garbage plaintext.
    var bad_ct2 = ct2;
    bad_ct2[0] +%= 1;
    var junk: [msg2.len]u8 = undefined;
    receiver_ctx.open("", &bad_ct2, &junk) catch |err| switch (err) {
        error.DecryptionFailed => std.debug.print("tampered ciphertext correctly rejected\n", .{}),
        else => return err,
    };

    // Both sides derive the same exporter secret from the same Context
    // parameters without ever sealing/opening a message through it — the
    // path an MLS-style external-init would use (RFC 9420 §8.3/§12.4).
    const suite_id = hpke.suite.suiteId(Kem.kem_id, @intFromEnum(hpke.KdfId.hkdf_sha256), @intFromEnum(hpke.AeadId.chacha20poly1305));
    var sender_export: [32]u8 = undefined;
    try sender_ctx.exportSecret(&suite_id, "session-key", &sender_export);
    var receiver_export: [32]u8 = undefined;
    try receiver_ctx.exportSecret(&suite_id, "session-key", &receiver_export);
    std.debug.print("exported secrets match: {}\n", .{std.mem.eql(u8, &sender_export, &receiver_export)});
}
