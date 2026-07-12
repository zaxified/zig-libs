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

        const finished = try opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2);
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
        opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, tampered),
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
    const finished = try opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2);
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
        opaque_pake.generateKE3(client.state, identitiesOf(v), v.context, server.ke2),
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
        opaque_pake.generateKE3(client.state, wrong_identities, v.context, server.ke2),
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
        [_]u8{0x11} ** 32, // envelope_nonce
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
    const finished = try opaque_pake.generateKE3(client.state, identities, context, server.ke2);
    const server_session_key = try opaque_pake.serverFinish(server.state, finished.ke3);

    // Both sides agree on the session key; the login-recovered
    // export_key equals the registration-time export_key.
    try testing.expectEqualSlices(u8, &finished.session_key, &server_session_key);
    try testing.expectEqualSlices(u8, &registered.export_key, &finished.export_key);

    // Sanity: fresh keys differ from the RFC vector's.
    try testing.expect(!std.mem.eql(u8, &finished.session_key, &kat.real_1.session_key));
}
