// SPDX-License-Identifier: MIT

//! What a JWT ES256 signer does with `p256`: generate a P-256 key pair on
//! the fast curve, sign a request payload, verify it back, then show that a
//! tampered payload is rejected by name rather than by silent success.
//!
//! `p256.EcdsaP256Sha256` is the drop-in for
//! `std.crypto.sign.ecdsa.EcdsaP256Sha256` — same `KeyPair`/`Signature`
//! surface, same wire encoding — just running on p256's own accelerated
//! field/group arithmetic instead of std's portable fiat-crypto core.

const std = @import("std");
const p256 = @import("p256");

pub fn main() !void {
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Ecdsa = p256.EcdsaP256Sha256;
    const key_pair = Ecdsa.KeyPair.generate(io);

    const payload = "{\"sub\":\"user-42\",\"exp\":1999999999}";
    const sig = try Ecdsa.KeyPair.sign(key_pair, payload, null);

    // The raw fixed-width r||s encoding is what a JWS ES256 signature
    // segment carries (base64url elsewhere is the caller's job, not this
    // module's).
    const raw = sig.toBytes();
    std.debug.print("signature: {d} bytes, r||s fixed-width\n", .{raw.len});

    try sig.verify(payload, key_pair.public_key);
    std.debug.print("verify(original payload): ok\n", .{});

    // A one-byte tamper on the claims must be rejected by NAME, not just
    // "some error" — a token validator branches on this.
    var tampered_buf: [payload.len]u8 = undefined;
    @memcpy(&tampered_buf, payload);
    tampered_buf[tampered_buf.len - 2] = '0'; // exp ...9 -> ...0
    if (sig.verify(&tampered_buf, key_pair.public_key)) |_| {
        std.debug.print("unexpected: tampered payload verified\n", .{});
    } else |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("verify(tampered payload): SignatureVerificationFailed (expected)\n", .{}),
        else => return err,
    }

    // `sign` derives its nonce deterministically (RFC 6979-style) rather than
    // from caller randomness, so signing the same payload again with the
    // same key reproduces the exact same signature bytes — no nonce-reuse
    // hazard for a caller that signs the same claims twice.
    const sig_again = try Ecdsa.KeyPair.sign(key_pair, payload, null);
    std.debug.print("re-sign same payload: identical bytes = {}\n", .{std.mem.eql(u8, &raw, &sig_again.toBytes())});
}
