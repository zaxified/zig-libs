// SPDX-License-Identifier: MIT
//! KAT tests: every assertion below pins the public flows of
//! `root.zig` byte-exact to RFC 9807 Appendix C.1's official
//! OPAQUE-3DH "Real" vectors for ristretto255-SHA-512 (C.1.1 without
//! identities, C.1.2 with client_identity = "alice" / server_identity
//! = "bob"), feeding the vectors' fixed randomness (blinds, nonces,
//! keyshare seeds) through the caller-supplied-randomness API:
//!   1. registration_request / registration_response /
//!      registration_upload (incl. the envelope and client_public_key
//!      intermediates) reproduce byte-exact;
//!   2. KE1, KE2, KE3 reproduce byte-exact;
//!   3. export_key and session_key reproduce byte-exact on BOTH sides
//!      and agree;
//!   4. a tampered KE2 server_mac fails closed on the client and a
//!      tampered KE3 client_mac fails closed on the server (typed
//!      errors); a wrong password fails closed as EnvelopeRecovery;
//!   5. a fresh end-to-end registration + login round trip with
//!      non-vector randomness agrees on session_key and export_key.
//! The unexposed intermediates the RFC also publishes (`oprf_key`,
//! `auth_key`, `randomized_password`, `handshake_secret`,
//! `server_mac_key`, `client_mac_key`) are pinned transitively: each
//! feeds the byte-exact outputs above through an injective pipeline
//! (any deviation would flip the corresponding output comparison).

const std = @import("std");
const testing = std.testing;
const opaque_pake = @import("root.zig");
const kat = @import("kat_vectors.zig");

const vectors = [_]kat.RealVector{ kat.real_1, kat.real_2 };

fn identitiesOf(v: kat.RealVector) opaque_pake.Identities {
    return .{ .client = v.client_identity, .server = v.server_identity };
}

/// Runs the vector's registration flow and returns the record + export
/// key (asserting every published output on the way).
fn registerFromVector(v: kat.RealVector) !opaque_pake.FinalizeRegistrationResult {
    const request = try opaque_pake.createRegistrationRequest(v.password, v.blind_registration);
    try testing.expectEqualSlices(u8, &v.registration_request, &request.toBytes());

    const response = try opaque_pake.createRegistrationResponse(
        request,
        v.server_public_key,
        v.credential_identifier,
        v.oprf_seed,
    );
    try testing.expectEqualSlices(u8, &v.registration_response, &response.toBytes());

    const finalized = try opaque_pake.finalizeRegistrationRequest(
        v.password,
        v.blind_registration,
        response,
        identitiesOf(v),
        v.envelope_nonce,
        .{},
    );
    return finalized;
}

// ── (1) registration reproduces C.1.x byte-exact ─────────────────────────

test "registration: request, response, record, envelope, export_key match C.1.1 + C.1.2" {
    for (vectors) |v| {
        const finalized = try registerFromVector(v);
        // The full RegistrationRecord (registration_upload) — this also
        // pins masking_key, which the RFC does not publish standalone.
        try testing.expectEqualSlices(u8, &v.registration_upload, &finalized.record.toBytes());
        // Published intermediates carried inside the record.
        try testing.expectEqualSlices(u8, &v.client_public_key, &finalized.record.client_public_key);
        try testing.expectEqualSlices(u8, &v.envelope, &finalized.record.envelope.toBytes());
        // export_key already at registration time.
        try testing.expectEqualSlices(u8, &v.export_key, &finalized.export_key);
    }
}

// ── (2) + (3) login AKE reproduces KE1/KE2/KE3 and the output keys ───────

test "login: KE1, KE2, KE3, session_key, export_key match C.1.1 + C.1.2 on both sides" {
    for (vectors) |v| {
        const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);

        const client = try opaque_pake.generateKE1(
            v.password,
            v.blind_login,
            v.client_nonce,
            v.client_keyshare_seed,
        );
        try testing.expectEqualSlices(u8, &v.ke1, &client.ke1.toBytes());

        const server = try opaque_pake.generateKE2(
            v.server_private_key,
            v.server_public_key,
            record,
            v.credential_identifier,
            v.oprf_seed,
            client.ke1,
            identitiesOf(v),
            v.context,
            v.masking_nonce,
            v.server_nonce,
            v.server_keyshare_seed,
        );
        try testing.expectEqualSlices(u8, &v.ke2, &server.ke2.toBytes());

        const finished = try opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2, .{});
        try testing.expectEqualSlices(u8, &v.ke3, &finished.ke3.toBytes());
        // (3) client-side outputs match the vector...
        try testing.expectEqualSlices(u8, &v.session_key, &finished.session_key);
        try testing.expectEqualSlices(u8, &v.export_key, &finished.export_key);

        // ...and the server independently derives the SAME session_key.
        const server_session_key = try opaque_pake.serverFinish(server.state, finished.ke3);
        try testing.expectEqualSlices(u8, &v.session_key, &server_session_key);
        try testing.expectEqualSlices(u8, &finished.session_key, &server_session_key);
    }
}

// ── (4) tampering / wrong password fail closed ───────────────────────────

test "tampered KE2 server_mac fails closed on the client (ServerAuthentication)" {
    const v = kat.real_1;
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    var tampered = server.ke2;
    tampered.auth_response.server_mac[0] ^= 0x01;
    try testing.expectError(
        error.ServerAuthentication,
        opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, tampered, .{}),
    );
}

test "tampered KE3 client_mac fails closed on the server (ClientAuthentication)" {
    const v = kat.real_1;
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    const finished = try opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2, .{});
    var tampered = finished.ke3;
    tampered.client_mac[tampered.client_mac.len - 1] ^= 0x80;
    try testing.expectError(error.ClientAuthentication, opaque_pake.serverFinish(server.state, tampered));
}

test "wrong password fails closed on the client (EnvelopeRecovery)" {
    const v = kat.real_1;
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try opaque_pake.generateKE1(
        "definitely not the password",
        v.blind_login,
        v.client_nonce,
        v.client_keyshare_seed,
    );
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    try testing.expectError(
        error.EnvelopeRecovery,
        opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2, .{}),
    );
}

test "mismatched identities fail closed on the client (EnvelopeRecovery)" {
    // Registered without identities (real_1's record), but the client
    // attempts recovery pinning an identity the envelope never bound.
    const v = kat.real_1;
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const wrong_identities = opaque_pake.Identities{ .client = "mallory", .server = null };
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        wrong_identities,
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    try testing.expectError(
        error.EnvelopeRecovery,
        opaque_pake.generateKE3(client.state, wrong_identities, v.context, server.ke2, .{}),
    );
}

test "identity-element client_public_keyshare in KE1 is rejected (InvalidPublicKey)" {
    // §6.4.1.1's "DH shared secret MUST NOT be the identity" / §10.7
    // input validation, exercised end to end through generateKE2: the
    // ristretto255 identity element (32 zero bytes) MUST fail
    // Element.fromBytes's decode-time identity rejection, not just be
    // accepted and silently produce a degenerate shared secret. No
    // other test in this suite ever supplies a malformed/identity
    // keyshare, so this path was previously unexercised.
    const v = kat.real_1;
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    var poisoned_ke1 = client.ke1;
    poisoned_ke1.auth_request.client_public_keyshare = [_]u8{0} ** opaque_pake.Npk; // identity element

    try testing.expectError(error.InvalidPublicKey, opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        poisoned_ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    ));
}

test "identity-element server_public_keyshare in KE2 is rejected (InvalidPublicKey) on the client" {
    // The mirror image on the client side: generateKE3 must reject a
    // KE2 whose server_public_keyshare is the identity element, rather
    // than deriving a degenerate DH1/DH3 shared secret from it.
    const v = kat.real_1;
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    var poisoned_ke2 = server.ke2;
    poisoned_ke2.auth_response.server_public_keyshare = [_]u8{0} ** opaque_pake.Npk; // identity element

    try testing.expectError(
        error.InvalidPublicKey,
        opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, poisoned_ke2, .{}),
    );
}

// ── (5) fresh end-to-end round trip (non-vector randomness) ──────────────

test "fresh end-to-end registration + login agree on session_key and export_key" {
    // Deterministic NON-vector "randomness" (this is a test fixture,
    // not CSPRNG discipline — production callers must draw all of
    // these fresh from a CSPRNG).
    var wide: [64]u8 = undefined;
    for (&wide, 0..) |*b, i| b.* = @truncate(i *% 101 +% 7);
    const blind_reg = opaque_pake.scalarFromWideBytes(wide);
    for (&wide, 0..) |*b, i| b.* = @truncate(i *% 59 +% 3);
    const blind_login = opaque_pake.scalarFromWideBytes(wide);

    const server_key_seed = [_]u8{0xa7} ** 32;
    const server_keys = try opaque_pake.deriveAkeKeyPair(server_key_seed);
    const oprf_seed = [_]u8{0x5c} ** 64;
    const credential_identifier = "user-42";
    const password = "hunter2, but longer";
    const identities = opaque_pake.Identities{ .client = "user-42", .server = "example.com" };
    const context = "zig-libs opaque test";

    // Registration.
    const request = try opaque_pake.createRegistrationRequest(password, blind_reg);
    const response = try opaque_pake.createRegistrationResponse(
        request,
        server_keys.public_key,
        credential_identifier,
        oprf_seed,
    );
    const registered = try opaque_pake.finalizeRegistrationRequest(
        password,
        blind_reg,
        response,
        identities,
        [_]u8{0x11} ** 32, // envelope_nonce,
        .{},
    );

    // Login.
    const client = try opaque_pake.generateKE1(
        password,
        blind_login,
        [_]u8{0x22} ** 32, // client_nonce
        [_]u8{0x33} ** 32, // client_keyshare_seed
    );
    const server = try opaque_pake.generateKE2(
        server_keys.private_key,
        server_keys.public_key,
        registered.record,
        credential_identifier,
        oprf_seed,
        client.ke1,
        identities,
        context,
        [_]u8{0x44} ** 32, // masking_nonce
        [_]u8{0x55} ** 32, // server_nonce
        [_]u8{0x66} ** 32, // server_keyshare_seed
    );
    const finished = try opaque_pake.generateKE3(client.state, identities, context, server.ke2, .{});
    const server_session_key = try opaque_pake.serverFinish(server.state, finished.ke3);

    // Both sides agree on the session key; the login-recovered
    // export_key equals the registration-time export_key.
    try testing.expectEqualSlices(u8, &finished.session_key, &server_session_key);
    try testing.expectEqualSlices(u8, &registered.export_key, &finished.export_key);

    // Sanity: fresh keys differ from the RFC vector's.
    try testing.expect(!std.mem.eql(u8, &finished.session_key, &kat.real_1.session_key));
}

// ── audit M6: a pluggable Ksf actually participates in the derivation ────
//
// RFC 9807 §7: the KSF "is determined by the application" (collision
// resistance is the only hard requirement); Appendix C's own test vectors
// use Identity purely for reproducibility, NOT as a production
// recommendation -- §7's three configurations RECOMMENDED absent an
// application-specific profile all use a real KSF (two Argon2id, one
// scrypt). `Ksf.identity` stays the default (this module has no
// `Allocator`/`Io` dependency anywhere else), but every entry point that
// calls `randomizedPassword` now accepts any `Ksf`.
//
// Argon2id needs an `Allocator` and a `std.Io` -- this module's `Ksf`
// carries neither; the CALLER (here, the test) supplies both via `ctx`.
const Argon2Ksf = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    salt: [16]u8,
    params: std.crypto.pwhash.argon2.Params,
    fail: bool = false, // fault injection, see the KsfFailed test below

    fn stretchFn(ctx: ?*anyopaque, in: [64]u8, out: *[64]u8) error{KsfFailed}!void {
        const self: *Argon2Ksf = @ptrCast(@alignCast(ctx.?));
        if (self.fail) return error.KsfFailed;
        std.crypto.pwhash.argon2.kdf(self.allocator, out, &in, &self.salt, self.params, .argon2id, self.io) catch
            return error.KsfFailed;
    }

    fn ksf(self: *Argon2Ksf) opaque_pake.Ksf {
        return .{ .ctx = self, .stretchFn = stretchFn };
    }
};

test "M6: a real KSF (Argon2id) changes session_key/export_key, and matching KSFs on both sides still agree" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // RFC 9807 §7's own recommended Argon2id config uses S = zeroes(16);
    // OWASP's t/m/p (cheaper than the RFC's 2^21 KiB example) so this test
    // runs in a reasonable time while still exercising a real KDF, not a
    // toy stand-in.
    var argon2: Argon2Ksf = .{
        .allocator = testing.allocator,
        .io = io,
        .salt = [_]u8{0} ** 16,
        .params = std.crypto.pwhash.argon2.Params.owasp_2id,
    };

    var wide: [64]u8 = undefined;
    for (&wide, 0..) |*b, i| b.* = @truncate(i *% 101 +% 7);
    const blind_reg = opaque_pake.scalarFromWideBytes(wide);
    for (&wide, 0..) |*b, i| b.* = @truncate(i *% 59 +% 3);
    const blind_login = opaque_pake.scalarFromWideBytes(wide);
    const server_key_seed = [_]u8{0xa7} ** 32;
    const server_keys = try opaque_pake.deriveAkeKeyPair(server_key_seed);
    const oprf_seed = [_]u8{0x5c} ** 64;
    const credential_identifier = "user-42";
    const password = "hunter2, but longer";
    const identities = opaque_pake.Identities{ .client = "user-42", .server = "example.com" };
    const context = "zig-libs opaque test";

    const request = try opaque_pake.createRegistrationRequest(password, blind_reg);
    const response = try opaque_pake.createRegistrationResponse(
        request,
        server_keys.public_key,
        credential_identifier,
        oprf_seed,
    );
    const registered = try opaque_pake.finalizeRegistrationRequest(
        password,
        blind_reg,
        response,
        identities,
        [_]u8{0x11} ** 32,
        .{ .ksf = argon2.ksf() },
    );

    const client = try opaque_pake.generateKE1(
        password,
        blind_login,
        [_]u8{0x22} ** 32,
        [_]u8{0x33} ** 32,
    );
    const server = try opaque_pake.generateKE2(
        server_keys.private_key,
        server_keys.public_key,
        registered.record,
        credential_identifier,
        oprf_seed,
        client.ke1,
        identities,
        context,
        [_]u8{0x44} ** 32,
        [_]u8{0x55} ** 32,
        [_]u8{0x66} ** 32,
    );
    // Matching Argon2id on both sides: still a normal, successful login.
    const finished = try opaque_pake.generateKE3(client.state, identities, context, server.ke2, .{ .ksf = argon2.ksf() });
    const server_session_key = try opaque_pake.serverFinish(server.state, finished.ke3);
    try testing.expectEqualSlices(u8, &finished.session_key, &server_session_key);
    try testing.expectEqualSlices(u8, &registered.export_key, &finished.export_key);

    // The actual M6 claim: this is NOT the same as the identity-KSF run
    // with byte-for-byte identical everything-else above (same password,
    // same blinds, same seeds, same nonces) -- the KSF genuinely
    // participates, it is not dead code plugged into an ignored parameter.
    try testing.expect(!std.mem.eql(u8, &finished.session_key, &kat.real_1.session_key));

    // A mismatched KSF between registration and login is exactly as fatal
    // as a wrong password (`randomized_password` differs either way) --
    // fails closed via the existing envelope MAC, not a new failure mode.
    const wrong_client = try opaque_pake.generateKE1(password, blind_login, [_]u8{0x22} ** 32, [_]u8{0x33} ** 32);
    const wrong_server = try opaque_pake.generateKE2(
        server_keys.private_key,
        server_keys.public_key,
        registered.record,
        credential_identifier,
        oprf_seed,
        wrong_client.ke1,
        identities,
        context,
        [_]u8{0x44} ** 32,
        [_]u8{0x55} ** 32,
        [_]u8{0x66} ** 32,
    );
    try testing.expectError(
        error.EnvelopeRecovery,
        opaque_pake.generateKE3(wrong_client.state, identities, context, wrong_server.ke2, .{}), // .identity, not argon2
    );
}

test "M6: a failing KSF propagates error.KsfFailed, not silently swallowed or panicking" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var argon2: Argon2Ksf = .{
        .allocator = testing.allocator,
        .io = threaded.io(),
        .salt = [_]u8{0} ** 16,
        .params = std.crypto.pwhash.argon2.Params.owasp_2id,
        .fail = true,
    };

    var wide: [64]u8 = undefined;
    for (&wide, 0..) |*b, i| b.* = @truncate(i *% 101 +% 7);
    const blind_reg = opaque_pake.scalarFromWideBytes(wide);
    const server_key_seed = [_]u8{0xa7} ** 32;
    const server_keys = try opaque_pake.deriveAkeKeyPair(server_key_seed);
    const oprf_seed = [_]u8{0x5c} ** 64;
    const identities = opaque_pake.Identities{ .client = "user-42", .server = "example.com" };

    const request = try opaque_pake.createRegistrationRequest("hunter2", blind_reg);
    const response = try opaque_pake.createRegistrationResponse(request, server_keys.public_key, "user-42", oprf_seed);
    try testing.expectError(
        error.KsfFailed,
        opaque_pake.finalizeRegistrationRequest(
            "hunter2",
            blind_reg,
            response,
            identities,
            [_]u8{0x11} ** 32,
            .{ .ksf = argon2.ksf() },
        ),
    );
}

// ── (6) full-width MAC ladder (A1/opaque.md H1) ──────────────────────────
//
// The two tamper tests above (§4) each flip exactly one byte — byte 0 for
// server_mac, the LAST byte for client_mac — because that is where the
// vectors' own fixture happened to differ. That pins "the check fires on
// SOME byte", not "the check covers every byte". A comparison narrowed to
// a byte range that happens to include position 0 (or the last byte) would
// still pass both tests with 17/17 green — measured in the audit: a
// same-shaped mutant that compared only `server_mac[0..1]` accepted 25 of
// 4096 fully-forged server_macs (0.61%), and one comparing only
// `auth_tag[0..1]` let 14 of 4096 wrong passwords through the envelope
// check — while the existing suite stayed green throughout. These three
// tests flip every one of the `Nm` = 64 bytes individually (not just the
// two the fixture already exercised) and require EVERY position to be
// caught, closing that gap without needing to hand-build a weakened binary
// to prove it: a suite that only ever tampers 2 of 64 byte positions
// cannot, by construction, fail to notice a comparison that only checks
// those same 2 positions (or misses them and checks different ones) — the
// only way to know the check covers position k is to tamper position k.
test "H1: every byte of the envelope auth_tag is checked, not just some" {
    const v = kat.real_1;
    const base = try registerFromVector(v);
    var i: usize = 0;
    while (i < opaque_pake.Nm) : (i += 1) {
        var tampered_record = base.record;
        tampered_record.envelope.auth_tag[i] ^= 0x01;

        const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
        const server = try opaque_pake.generateKE2(
            v.server_private_key,
            v.server_public_key,
            tampered_record,
            v.credential_identifier,
            v.oprf_seed,
            client.ke1,
            identitiesOf(v),
            v.context,
            v.masking_nonce,
            v.server_nonce,
            v.server_keyshare_seed,
        );
        try testing.expectError(
            error.EnvelopeRecovery,
            opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2, .{}),
        );
    }
    // Positive control: the untampered record still logs in.
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        base.record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    _ = try opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2, .{});
}

test "H1: every byte of KE2's server_mac is checked, not just byte 0" {
    const v = kat.real_1;
    const base = try registerFromVector(v);
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        base.record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    var i: usize = 0;
    while (i < opaque_pake.Nm) : (i += 1) {
        var tampered = server.ke2;
        tampered.auth_response.server_mac[i] ^= 0x01;
        try testing.expectError(
            error.ServerAuthentication,
            opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, tampered, .{}),
        );
    }
    // Positive control: the untampered KE2 still completes.
    _ = try opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2, .{});
}

test "H1: every byte of KE3's client_mac is checked, not just the last byte" {
    const v = kat.real_1;
    const base = try registerFromVector(v);
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        base.record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    const finished = try opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2, .{});
    var i: usize = 0;
    while (i < opaque_pake.Nm) : (i += 1) {
        var tampered = finished.ke3;
        tampered.client_mac[i] ^= 0x01;
        try testing.expectError(error.ClientAuthentication, opaque_pake.serverFinish(server.state, tampered));
    }
    // Positive control: the untampered KE3 still completes.
    _ = try opaque_pake.serverFinish(server.state, finished.ke3);
}

// ── (7) RFC 9807 Appendix C.2.1 -- the FAKE (unregistered-user) vector ───
//
// A1/opaque.md L3: SPEC.md used to say the fake-record response has
// "nothing new to pin" because it is the same `generateKE2` code path as
// a real one. C.2.1 is the ristretto255 FAKE vector and it IS runnable —
// it is also the only vector in this suite that exercises the §6.3.2.2
// user-enumeration defense end-to-end, which C.1's "Real" vectors cannot
// (there is no registered record to be missing). Bytes extracted
// mechanically from `rfc9807.txt` by `A1/repro/opaque/gen_fake_probe.py`,
// same method C1 uses for the "Real" vectors.

fn hx(comptime s: []const u8) [s.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        var out: [s.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch unreachable;
        return out;
    }
}

test "RFC 9807 C.2.1 fake credential response reproduces KE2 byte-exact" {
    const client_identity = comptime hx("616c696365");
    const server_identity = comptime hx("626f62");
    const oprf_seed = comptime hx("743fc168d1f826ad43738933e5adb23da6fb95f95a1b069f0daa0522d0a78b617f701fc6aa46d3e7981e70de7765dfcd6b1e13e3369a582eb8dc456b10aa53b0");
    const credential_identifier = comptime hx("31323334");
    const masking_nonce = comptime hx("9c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a6");
    const client_public_key = comptime hx("84f43f9492e19c22d8bdaa4447cc3d4db1cdb5427a9f852c4707921212c36251");
    const server_private_key = comptime hx("c788585ae8b5ba2942b693b849be0c0426384e41977c18d2e81fbe30fd7c9f06");
    const server_public_key = comptime hx("825f832667480f08b0c9069da5083ac4d0e9ee31b49c4e0310031fea04d52966");
    const server_nonce = comptime hx("1e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d12");
    const server_keyshare_seed = comptime hx("360b0937f47d45f6123a4d8f0d0c0814b6120d840ebb8bc5b4f6b62df07f78c2");
    const masking_key = comptime hx("39ebd51f0e39a07a1c2d2431995b0399bca9996c5d10014d6ebab4453dc10ce5cef38ed3df6e56bfff40c2d8dd4671c2b4cf63c3d54860f31fe40220d690bb71");
    const ke1 = comptime hx("b0a26dcaca2230b8f5e4b1bcab9c84b586140221bb8b2848486874b0be44890542d4e61ed3f8d64cdd3b9d153343eca15b9b0d5e388232793c6376bd2d9cfd0ab641d7f20a245a09f1d4dbb6e301661af7f352beb0791d055e48d3645232f77f");
    const ke2 = comptime hx("928f79ad8df21963e91411b9f55165ba833dea918f441db967cdc09521d229259c035896a043e70f897d87180c543e7a063b83c1bb728fbd189c619e27b6e5a632b5ab1bff96636144faa4f9f9afaac75dd88ea99cf5175902ae3f3b2195693f165f11929ba510a5978e64dcdabecbd7ee1e4380ce270e58fea58e6462d92964a1aaef72698bca1c673baeb04cc2bf7de5f3c2f5553464552d3a0f7698a9ca7f9c5e70c6cb1f706b2f175ab9d04bbd13926e816b6811a50b4aafa9799d5ed7971e10f6eeab2a7a420bf09da9b27a4639645622c46358de9cf7ae813055ae2d1298251c5ba55f6b0b2d58d9ff0c88fe4176484be62a96db6e2a8c4d431bd1bf27fe6c1d0537603835217d42ebf7b2581982732e74892fd28211b31ed33863f0beaf75ba6f59474c0aaf9d78a60a9b2f4cd24d7ab54131b3c8efa192df6b72db4c");
    const context = comptime hx("4f50415155452d504f43");

    // §6.3.2.2's fake record: this client_public_key/masking_key pair IS
    // the "randomly generated public key" the module doc comment (and
    // A1/opaque.md M1) now describes -- the RFC's own fixture for it,
    // not 32 uniform random bytes.
    const record = opaque_pake.RegistrationRecord{
        .client_public_key = client_public_key,
        .masking_key = masking_key,
        .envelope = opaque_pake.Envelope.fromBytes([_]u8{0} ** opaque_pake.Envelope.encoded_length),
    };
    const ke1_msg = opaque_pake.KE1.fromBytes(ke1);
    const res = try opaque_pake.generateKE2(
        server_private_key,
        server_public_key,
        record,
        &credential_identifier,
        oprf_seed,
        ke1_msg,
        .{ .client = &client_identity, .server = &server_identity },
        &context,
        masking_nonce,
        server_nonce,
        server_keyshare_seed,
    );
    try testing.expectEqualSlices(u8, &ke2, &res.ke2.toBytes());
}

// ── (8) RegistrationRecord.validate (A1/opaque.md L1) ────────────────────

test "M2: an identity/context past 0xffff bytes is a typed error, not a panic or a silent wrap" {
    // A1/opaque.md M2: `i2osp2`'s length prefix (used to bind identities
    // and context into the envelope MAC / AKE transcript) silently wraps
    // mod 65536 in ReleaseFast past this bound, and panics in Debug --
    // neither is a caller-visible, typed failure. `oversized` is one byte
    // past what a real allocation would ever need for a test, but the
    // check has to trigger on the byte count, not the content.
    const v = kat.real_1;
    const oversized_buf = std.testing.allocator.alloc(u8, 0x10000) catch return error.SkipZigTest;
    defer std.testing.allocator.free(oversized_buf);
    @memset(oversized_buf, 'x');

    try testing.expectError(
        error.IdentityTooLong,
        opaque_pake.finalizeRegistrationRequest(
            v.password,
            v.blind_registration,
            opaque_pake.RegistrationResponse.fromBytes(v.registration_response),
            .{ .client = oversized_buf, .server = null },
            v.envelope_nonce,
            .{},
        ),
    );

    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    try testing.expectError(
        error.IdentityTooLong,
        opaque_pake.generateKE2(
            v.server_private_key,
            v.server_public_key,
            record,
            v.credential_identifier,
            v.oprf_seed,
            client.ke1,
            .{ .client = oversized_buf, .server = null },
            v.context,
            v.masking_nonce,
            v.server_nonce,
            v.server_keyshare_seed,
        ),
    );
    try testing.expectError(
        error.IdentityTooLong,
        opaque_pake.generateKE2(
            v.server_private_key,
            v.server_public_key,
            record,
            v.credential_identifier,
            v.oprf_seed,
            client.ke1,
            identitiesOf(v),
            oversized_buf, // context, this time
            v.masking_nonce,
            v.server_nonce,
            v.server_keyshare_seed,
        ),
    );

    // Positive control: an ordinary vector-sized identity/context is fine.
    _ = try opaque_pake.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        identitiesOf(v),
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
}

test "L1: RegistrationRecord.validate catches a degenerate client_public_key" {
    const v = kat.real_1;
    // A genuine, registered record must validate...
    const good = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    try good.validate();
    // ...an upload whose client_public_key is the identity element
    // (the same degenerate value the KE1/KE2 keyshare tests above use)
    // must not.
    var poisoned = good;
    poisoned.client_public_key = [_]u8{0} ** opaque_pake.Npk;
    try testing.expectError(error.InvalidPublicKey, poisoned.validate());
}
