// SPDX-License-Identifier: MIT
//! RFC 9807 Appendix C, P256-SHA256 configuration, byte-exact through
//! `opaque.P256Sha256` (`kat_vectors_p256.zig`, generated from the RFC text):
//! C.1.5 (no identities) and C.1.6 (alice/bob) registration + login on both
//! sides, and the C.2.3 fake credential response.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const kv = @import("kat_vectors_p256.zig");

const O = root.P256Sha256;

fn field(v: kv.Vector, name: []const u8) ?[]const u8 {
    for (v.fields) |f| if (std.mem.eql(u8, f[0], name)) return f[1];
    return null;
}

/// Decode a named hex field into a fixed array (length checked).
fn arr(comptime n: usize, v: kv.Vector, name: []const u8) ![n]u8 {
    const s = field(v, name) orelse return error.MissingField;
    if (s.len != 2 * n) return error.BadFieldLength;
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

/// Decode a named hex field into `buf` (variable length).
fn bytes(buf: []u8, v: kv.Vector, name: []const u8) ![]const u8 {
    const s = field(v, name) orelse return error.MissingField;
    return std.fmt.hexToBytes(buf[0 .. s.len / 2], s);
}

fn expectField(v: kv.Vector, name: []const u8, actual: []const u8) !void {
    var buf: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, try bytes(&buf, v, name), actual);
}

fn runReal(v: kv.Vector) !void {
    var pw_buf: [64]u8 = undefined;
    var cid_buf: [16]u8 = undefined;
    var ctx_buf: [16]u8 = undefined;
    var ci_buf: [16]u8 = undefined;
    var si_buf: [16]u8 = undefined;
    const password = try bytes(&pw_buf, v, "password");
    const credential_identifier = try bytes(&cid_buf, v, "credential_identifier");
    const context = try bytes(&ctx_buf, v, "Context");
    const identities: O.Identities = .{
        .client = if (field(v, "client_identity") != null) try bytes(&ci_buf, v, "client_identity") else null,
        .server = if (field(v, "server_identity") != null) try bytes(&si_buf, v, "server_identity") else null,
    };
    const oprf_seed = try arr(O.Nh, v, "oprf_seed");
    const server_public_key = try arr(O.Npk, v, "server_public_key");
    const server_private_key = try arr(O.Nsk, v, "server_private_key");
    const blind_registration = try arr(O.Ns, v, "blind_registration");
    const blind_login = try arr(O.Ns, v, "blind_login");

    // Registration.
    const request = try O.createRegistrationRequest(password, &blind_registration);
    try expectField(v, "registration_request", &request.toBytes());
    const response = try O.createRegistrationResponse(request, server_public_key, credential_identifier, &oprf_seed);
    try expectField(v, "registration_response", &response.toBytes());
    var reg: O.FinalizeRegistrationResult = undefined;
    try O.finalizeRegistrationRequest(password, &blind_registration, response, identities, try arr(O.Nn, v, "envelope_nonce"), .identity, &reg);
    try expectField(v, "registration_upload", &reg.record.toBytes());
    try expectField(v, "client_public_key", &reg.record.client_public_key);
    try expectField(v, "envelope", &reg.record.envelope.toBytes());
    try expectField(v, "export_key", &reg.export_key);

    // Login, both sides.
    var ke1: O.GenerateKE1Result = undefined;
    try O.generateKE1(password, &blind_login, try arr(O.Nn, v, "client_nonce"), &(try arr(O.Nseed, v, "client_keyshare_seed")), &ke1);
    try expectField(v, "KE1", &ke1.ke1.toBytes());
    var ke2: O.GenerateKE2Result = undefined;
    try O.generateKE2(&server_private_key, server_public_key, reg.record, credential_identifier, &oprf_seed, ke1.ke1, identities, context, try arr(O.Nn, v, "masking_nonce"), try arr(O.Nn, v, "server_nonce"), &(try arr(O.Nseed, v, "server_keyshare_seed")), &ke2);
    try expectField(v, "KE2", &ke2.ke2.toBytes());
    var ke3: O.GenerateKE3Result = undefined;
    try O.generateKE3(&ke1.state, identities, context, ke2.ke2, .identity, &ke3);
    try expectField(v, "KE3", &ke3.ke3.toBytes());
    try expectField(v, "session_key", &ke3.session_key);
    try expectField(v, "export_key", &ke3.export_key);
    var server_session_key: [O.Nx]u8 = undefined;
    try O.serverFinish(&ke2.state, ke3.ke3, &server_session_key);
    try expectField(v, "session_key", &server_session_key);

    // A wrong password fails closed.
    var bad: O.GenerateKE3Result = undefined;
    var ke1b: O.GenerateKE1Result = undefined;
    try O.generateKE1("wrong password", &blind_login, try arr(O.Nn, v, "client_nonce"), &(try arr(O.Nseed, v, "client_keyshare_seed")), &ke1b);
    var ke2b: O.GenerateKE2Result = undefined;
    try O.generateKE2(&server_private_key, server_public_key, reg.record, credential_identifier, &oprf_seed, ke1b.ke1, identities, context, try arr(O.Nn, v, "masking_nonce"), try arr(O.Nn, v, "server_nonce"), &(try arr(O.Nseed, v, "server_keyshare_seed")), &ke2b);
    try testing.expectError(error.EnvelopeRecovery, O.generateKE3(&ke1b.state, identities, context, ke2b.ke2, .identity, &bad));
}

test "RFC 9807 C.1.5 P256-SHA256 registration + login byte-exact on both sides" {
    try runReal(kv.real_5);
}

test "RFC 9807 C.1.6 P256-SHA256 (alice/bob identities) registration + login byte-exact" {
    try runReal(kv.real_6);
}

test "RFC 9807 C.2.3 P256-SHA256 fake credential response reproduces KE2 byte-exact" {
    const v = kv.fake_3;
    var cid_buf: [16]u8 = undefined;
    var ctx_buf: [16]u8 = undefined;
    var ci_buf: [16]u8 = undefined;
    var si_buf: [16]u8 = undefined;
    const record = O.RegistrationRecord{
        .client_public_key = try arr(O.Npk, v, "client_public_key"),
        .masking_key = try arr(O.Nh, v, "masking_key"),
        .envelope = O.Envelope.fromBytes(@as([O.Envelope.encoded_length]u8, @splat(0))),
    };
    const oprf_seed = try arr(O.Nh, v, "oprf_seed");
    const server_private_key = try arr(O.Nsk, v, "server_private_key");
    var res: O.GenerateKE2Result = undefined;
    try O.generateKE2(
        &server_private_key,
        try arr(O.Npk, v, "server_public_key"),
        record,
        try bytes(&cid_buf, v, "credential_identifier"),
        &oprf_seed,
        O.KE1.fromBytes(try arr(O.KE1.encoded_length, v, "KE1")),
        .{ .client = try bytes(&ci_buf, v, "client_identity"), .server = try bytes(&si_buf, v, "server_identity") },
        try bytes(&ctx_buf, v, "Context"),
        try arr(O.Nn, v, "masking_nonce"),
        try arr(O.Nn, v, "server_nonce"),
        &(try arr(O.Nseed, v, "server_keyshare_seed")),
        &res,
    );
    try expectField(v, "KE2", &res.ke2.toBytes());
}

test "P256-SHA256 configuration sizes match RFC 9807 C.1.5.1" {
    try testing.expectEqual(@as(usize, 32), O.Nh);
    try testing.expectEqual(@as(usize, 33), O.Npk);
    try testing.expectEqual(@as(usize, 32), O.Nsk);
    try testing.expectEqual(@as(usize, 32), O.Nm);
    try testing.expectEqual(@as(usize, 32), O.Nx);
    try testing.expectEqual(@as(usize, 32), O.Nok);
    try testing.expectEqual(@as(usize, 98), O.KE1.encoded_length);
    try testing.expectEqual(@as(usize, 259), O.KE2.encoded_length);
}
