// SPDX-License-Identifier: MIT

//! What a messaging client does with `signal`: fetch Bob's published prekey
//! bundle, open a session with PQXDH while Bob is offline, seed a Double
//! Ratchet from it, and send the first message.
//!
//! The interesting part for a first-time consumer is the seam between the two
//! halves. PQXDH's associated data is 1632 bytes — it binds Bob's ML-KEM
//! prekey, because ML-KEM's ciphertext does not commit to the public key it
//! was made under — while the Double Ratchet's is 64. `ratchetAssociatedData`
//! is the documented bridge; passing the full value would not compile, which
//! is the point.

const std = @import("std");
const signal = @import("signal");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // ── Bob, ahead of time: publish a bundle to the server ────────────────
    //
    // Bob is offline for everything below this line. That asynchrony is the
    // whole reason PQXDH exists rather than a live handshake.
    const bob_ik = signal.x3dh.generateKeyPair(io);
    const signing_randomness: [64]u8 = @splat(0x5A); // from `io.random` in production
    const bob_spk = signal.generateSignedPreKey(bob_ik, 1, signing_randomness, io);
    const bob_opk_kp = signal.x3dh.generateKeyPair(io);
    // Every KEM prekey is signed, last-resort and one-time alike: a curve
    // prekey is authenticated by the DH against Bob's identity key, and a KEM
    // prekey has no such binding, so the signature is all there is.
    const bob_kem = signal.generateKemPreKey(bob_ik, 100, true, signing_randomness, io);

    const bundle: signal.PqPreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk.key_pair.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = bob_spk.signature,
        .one_time_prekey = bob_opk_kp.public_key,
        .one_time_prekey_id = 7,
        .kem_prekey = bob_kem.key_pair.public_key.toBytes(),
        .kem_prekey_id = bob_kem.id,
        .kem_prekey_signature = bob_kem.signature,
    };

    // ── Alice: open the session ───────────────────────────────────────────
    const alice_ik = signal.x3dh.generateKeyPair(io);

    // `pqInitiate` verifies BOTH of Bob's signatures before deriving
    // anything. Handling the two separately is worth the extra arm: they are
    // different keys on different rotation schedules, and "which one is
    // stale" is the first question when a bundle stops verifying.
    const opened = signal.pqInitiate(gpa, alice_ik, bundle, "", io) catch |err| switch (err) {
        error.KemPreKeyVerificationFailed => {
            std.debug.print("Bob's ML-KEM prekey signature is bad — refuse the bundle\n", .{});
            return;
        },
        error.SignedPreKeyVerificationFailed => {
            std.debug.print("Bob's curve prekey signature is bad — refuse the bundle\n", .{});
            return;
        },
        else => return err,
    };
    defer gpa.free(opened.message.ciphertext);

    std.debug.print("session opened: SK derived, KEM ciphertext {d} B, AD {d} B\n", .{
        opened.message.kem_ciphertext.len,
        opened.agreement.associated_data.len,
    });

    // ── Alice: seed the ratchet and send ──────────────────────────────────
    var alice_state = try signal.initAlice(
        opened.agreement.shared_secret,
        opened.agreement.ratchetAssociatedData(),
        bob_spk.key_pair.public_key,
        io,
    );
    defer alice_state.deinit(gpa);

    var msg = try alice_state.encrypt(gpa, "we should get lunch");
    defer msg.deinit(gpa);
    std.debug.print("sent {d} B of ciphertext under a PQ-derived root key\n", .{msg.ciphertext.len});

    // ── Bob, back online: reconstruct the same secret and read it ─────────
    const bob_agreement = try signal.pqRespond(bob_ik, bob_spk, .{ .key_pair = bob_opk_kp, .id = 7 }, bob_kem, opened.message);
    if (!std.mem.eql(u8, &bob_agreement.shared_secret, &opened.agreement.shared_secret))
        @panic("PQXDH disagreed across the two sides");

    var bob_state = signal.initBob(
        bob_agreement.shared_secret,
        bob_agreement.ratchetAssociatedData(),
        bob_spk.key_pair,
    );
    defer bob_state.deinit(gpa);

    const plaintext = try bob_state.decrypt(gpa, msg.header, msg.ciphertext, io);
    defer gpa.free(plaintext);
    std.debug.print("Bob read: {s}\n", .{plaintext});
}
