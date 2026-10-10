// SPDX-License-Identifier: MIT

//! What an SSH `ecdh-sha2-nistp521` + `ecdsa-sha2-nistp521` peer does with
//! `p521`: both sides generate ephemeral keys and agree on a shared secret
//! (one sends its point compressed), the server signs the exchange hash with
//! its host key, the client checks it from the SEC1 public key it received —
//! raw r‖s and DER — and a tampered hash is refused by name.

const std = @import("std");
const p521 = @import("p521");

pub fn main() !void {
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Ecdsa = p521.EcdsaP521Sha512;

    // Ephemeral ECDH keys, generated into place (no by-value copy of the
    // secret half).
    var client: Ecdsa.KeyPair = undefined;
    var server: Ecdsa.KeyPair = undefined;
    Ecdsa.KeyPair.generateInto(&client, io);
    Ecdsa.KeyPair.generateInto(&server, io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&client));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&server));

    const q_c = client.public_key.toUncompressedSec1(); // 133 bytes on the wire
    const q_s = server.public_key.toCompressedSec1(); // 67 bytes: also accepted

    var k_client: [66]u8 = undefined;
    var k_server: [66]u8 = undefined;
    defer std.crypto.secureZero(u8, &k_client);
    defer std.crypto.secureZero(u8, &k_server);
    try p521.ecdhInto(&k_client, &client.secret_key.bytes, &q_s);
    try p521.ecdhInto(&k_server, &server.secret_key.bytes, &q_c);
    if (!std.mem.eql(u8, &k_client, &k_server)) return error.SharedSecretsDiffer;
    std.debug.print("ecdh: both sides agree ({d}-byte x-coordinate)\n", .{k_client.len});

    // A malformed peer point is refused by name.
    var bad = q_c;
    bad[132] ^= 1;
    if (p521.ecdhInto(&k_client, &client.secret_key.bytes, &bad)) |_| {
        return error.OffCurvePointAccepted;
    } else |err| switch (err) {
        error.InvalidEncoding => std.debug.print("ecdh(off-curve peer): InvalidEncoding (expected)\n", .{}),
        else => return err,
    }

    // The server's host key signs the exchange hash.
    var host: Ecdsa.KeyPair = undefined;
    Ecdsa.KeyPair.generateInto(&host, io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&host));
    var exchange_hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&(q_c ++ q_s ++ k_server), &exchange_hash, .{});
    const sig = try host.sign(&exchange_hash, null);

    // The client has only the host key's SEC1 bytes and the signature.
    const host_pub = try Ecdsa.PublicKey.fromSec1(&host.public_key.toUncompressedSec1());
    try sig.verify(&exchange_hash, host_pub);
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);
    try (try Ecdsa.Signature.fromDer(der)).verify(&exchange_hash, host_pub);
    std.debug.print("host signature: ok (raw {d} bytes, DER {d} bytes)\n", .{ sig.toBytes().len, der.len });

    var tampered = exchange_hash;
    tampered[0] ^= 0x80;
    if (sig.verify(&tampered, host_pub)) |_| {
        return error.TamperedHashUnexpectedlyVerified;
    } else |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("verify(tampered hash): SignatureVerificationFailed (expected)\n", .{}),
        else => return err,
    }
}
