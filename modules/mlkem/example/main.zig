// SPDX-License-Identifier: MIT

//! What the two sides of a post-quantum key exchange (a TLS 1.3 `MLKEM768`
//! share, an HPKE ML-KEM KEM) do with `mlkem`: the receiver generates a key
//! pair with the FIPS 140-3 pairwise check and stores its 64-byte seed; the
//! sender imports the encapsulation key and encapsulates; the receiver
//! decapsulates — from the live key and from a key re-derived from the stored
//! seed. A tampered ciphertext yields the implicit-rejection key, a
//! non-canonical encapsulation key and an inconsistent decapsulation key are
//! refused by name.

const std = @import("std");
const mlkem = @import("mlkem");

const K = mlkem.MLKem768;

pub fn main() !void {
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Receiver: a key pair, generated into place (the struct is ~10 KiB: it
    // caches the expanded matrix), with the pairwise consistency test.
    var receiver: K.KeyPair = undefined;
    try K.KeyPair.tryGenerateInto(&receiver, io, .{ .pairwise_check = true });
    defer std.crypto.secureZero(u8, std.mem.asBytes(&receiver));
    const ek = receiver.public_key.toBytes(); // 1184 bytes on the wire

    // Private-key storage in the seed form (64 bytes instead of 2400).
    var seed = receiver.secret_key.seedBytes().?;
    defer std.crypto.secureZero(u8, &seed);

    // Sender: import the encapsulation key (modulus check) and encapsulate.
    const sender_pk = try K.PublicKey.fromBytes(&ek);
    var enc = try sender_pk.tryEncaps(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&enc));

    // Receiver: decapsulate with the live key …
    var ss = receiver.secret_key.decaps(&enc.ciphertext);
    defer std.crypto.secureZero(u8, &ss);
    if (!std.crypto.timing_safe.eql([32]u8, ss, enc.shared_secret)) return error.SharedSecretsDiffer;
    std.debug.print("encaps/decaps: both sides agree ({d}-byte secret, {d}-byte ciphertext)\n", .{ ss.len, enc.ciphertext.len });

    // … and with the key re-derived from the stored seed.
    var restored: K.KeyPair = undefined;
    K.KeyPair.generateDeterministicInto(&restored, &seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&restored));
    var ss2 = restored.secret_key.decaps(&enc.ciphertext);
    defer std.crypto.secureZero(u8, &ss2);
    if (!std.crypto.timing_safe.eql([32]u8, ss2, enc.shared_secret)) return error.SeedRestoreDiffers;
    std.debug.print("seed form: the restored key decapsulates the same secret\n", .{});

    // A tampered ciphertext does not fail: it yields J(z ‖ c), unrelated to
    // the sender's secret (implicit rejection, FIPS 203 Algorithm 18).
    var bad_ct = enc.ciphertext;
    bad_ct[0] ^= 1;
    var ss_bad = receiver.secret_key.decaps(&bad_ct);
    defer std.crypto.secureZero(u8, &ss_bad);
    if (std.crypto.timing_safe.eql([32]u8, ss_bad, enc.shared_secret)) return error.TamperedCiphertextAccepted;
    std.debug.print("tampered ciphertext: implicit-rejection key (expected)\n", .{});

    // A coefficient ≥ q in the encapsulation key is refused by name.
    var bad_ek = ek;
    bad_ek[0] = 0xff;
    bad_ek[1] |= 0x0f;
    if (K.PublicKey.fromBytes(&bad_ek)) |_| {
        return error.NonCanonicalKeyAccepted;
    } else |err| switch (err) {
        error.NonCanonical => std.debug.print("fromBytes(coefficient 4095): NonCanonical (expected)\n", .{}),
        else => return err,
    }

    // An expanded decapsulation key whose H(ek) does not match is refused.
    var dk = receiver.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &dk);
    dk[K.SecretKey.encoded_length - 33] ^= 1; // last byte of H(ek)
    if (K.SecretKey.fromBytes(&dk)) |_| {
        return error.InconsistentKeyAccepted;
    } else |err| switch (err) {
        error.InconsistentKey => std.debug.print("SecretKey.fromBytes(bad H(ek)): InconsistentKey (expected)\n", .{}),
        else => return err,
    }
}
