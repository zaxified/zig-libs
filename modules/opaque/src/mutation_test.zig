// SPDX-License-Identifier: MIT
//! Tests added by the whole-module mutation of `protocol.zig` /
//! `burn.zig`: wire fields read from the right region (with bytes that do not
//! repeat inside a message), the `I2OSP(len, 2)` prefix, the identity / context
//! length bound at its exact edge, and the error code of a malformed peer
//! element reaching the OPRF finalisation.

const std = @import("std");
const testing = std.testing;
const opaque_pake = @import("root.zig");
const shim = @import("test_shim.zig");
const kat = @import("kat_vectors.zig");

/// Bytes with no period of 256 (`i * 37 + 11` alone repeats every 256 bytes,
/// and a `KE2` is 320 bytes long, so a field read from 256 bytes too early
/// looked right).
fn wireFill(comptime n: usize) [n]u8 {
    var b: [n]u8 = undefined;
    for (&b, 0..) |*x, i| x.* = @truncate(i *% 37 +% (i >> 8) *% 101 +% 11);
    return b;
}

fn checkWire(comptime O: type) !void {
    const b = wireFill(O.KE2.encoded_length);
    const cr = O.CredentialResponse.encoded_length;

    const ke2 = O.KE2.fromBytes(b);
    try testing.expectEqualSlices(u8, b[0..O.Noe], &ke2.credential_response.evaluated_message);
    try testing.expectEqualSlices(u8, b[O.Noe..][0..O.Nn], &ke2.credential_response.masking_nonce);
    try testing.expectEqualSlices(u8, b[O.Noe + O.Nn .. cr], &ke2.credential_response.masked_response);
    try testing.expectEqualSlices(u8, b[cr..][0..O.Nn], &ke2.auth_response.server_nonce);
    try testing.expectEqualSlices(u8, b[cr + O.Nn ..][0..O.Npk], &ke2.auth_response.server_public_keyshare);
    try testing.expectEqualSlices(u8, b[cr + O.Nn + O.Npk ..], &ke2.auth_response.server_mac);
    try testing.expectEqualSlices(u8, &b, &ke2.toBytes());

    const cresp = O.CredentialResponse.fromBytes(b[0..cr].*);
    try testing.expectEqualSlices(u8, b[0..O.Noe], &cresp.evaluated_message);
    try testing.expectEqualSlices(u8, b[O.Noe..][0..O.Nn], &cresp.masking_nonce);
    try testing.expectEqualSlices(u8, b[O.Noe + O.Nn .. cr], &cresp.masked_response);
    try testing.expectEqualSlices(u8, b[0..cr], &cresp.toBytes());

    const ke1 = O.KE1.fromBytes(b[0..O.KE1.encoded_length].*);
    try testing.expectEqualSlices(u8, b[0..O.Noe], &ke1.credential_request.blinded_message);
    try testing.expectEqualSlices(u8, b[O.Noe..][0..O.Nn], &ke1.auth_request.client_nonce);
    try testing.expectEqualSlices(u8, b[O.Noe + O.Nn ..][0..O.Npk], &ke1.auth_request.client_public_keyshare);
    try testing.expectEqualSlices(u8, b[0..O.KE1.encoded_length], &ke1.toBytes());

    const resp = O.RegistrationResponse.fromBytes(b[0..O.RegistrationResponse.encoded_length].*);
    try testing.expectEqualSlices(u8, b[0..O.Noe], &resp.evaluated_message);
    try testing.expectEqualSlices(u8, b[O.Noe..][0..O.Npk], &resp.server_public_key);
    try testing.expectEqualSlices(u8, b[0..O.RegistrationResponse.encoded_length], &resp.toBytes());

    const rec = O.RegistrationRecord.fromBytes(b[0..O.RegistrationRecord.encoded_length].*);
    try testing.expectEqualSlices(u8, b[0..O.Npk], &rec.client_public_key);
    try testing.expectEqualSlices(u8, b[O.Npk..][0..O.Nh], &rec.masking_key);
    try testing.expectEqualSlices(u8, b[O.Npk + O.Nh ..][0..O.Nn], &rec.envelope.nonce);
    try testing.expectEqualSlices(u8, b[O.Npk + O.Nh + O.Nn ..][0..O.Nm], &rec.envelope.auth_tag);
    try testing.expectEqualSlices(u8, b[0..O.RegistrationRecord.encoded_length], &rec.toBytes());

    const env = O.Envelope.fromBytes(b[0..O.Envelope.encoded_length].*);
    try testing.expectEqualSlices(u8, b[0..O.Nn], &env.nonce);
    try testing.expectEqualSlices(u8, b[O.Nn..][0..O.Nm], &env.auth_tag);
    try testing.expectEqualSlices(u8, b[0..O.Envelope.encoded_length], &env.toBytes());

    const ke3 = O.KE3.fromBytes(b[0..O.Nm].*);
    try testing.expectEqualSlices(u8, b[0..O.Nm], &ke3.toBytes());
}

test "wire: every field of every message is read from, and written to, its own region (both configurations)" {
    try checkWire(opaque_pake.Ristretto255Sha512);
    try checkWire(opaque_pake.P256Sha256);
}

fn checkI2osp(comptime O: type) !void {
    const cases = [_]struct { len: usize, bytes: [2]u8 }{
        .{ .len = 0, .bytes = .{ 0x00, 0x00 } },
        .{ .len = 1, .bytes = .{ 0x00, 0x01 } },
        .{ .len = 255, .bytes = .{ 0x00, 0xff } },
        .{ .len = 256, .bytes = .{ 0x01, 0x00 } },
        .{ .len = 0x1234, .bytes = .{ 0x12, 0x34 } },
        .{ .len = 0xffff, .bytes = .{ 0xff, 0xff } },
    };
    for (cases) |c| try testing.expectEqualSlices(u8, &c.bytes, &O.i2osp2(c.len));
}

test "i2osp2 is the 2-byte big-endian length (RFC 9807 section 1.2), high byte included" {
    try checkI2osp(opaque_pake.Ristretto255Sha512);
    try checkI2osp(opaque_pake.P256Sha256);
}

const big: [0x10001]u8 = @splat('x');

fn checkBound(comptime O: type) !void {
    // Exactly 0xffff is accepted, 0x10000 is refused, for each of the three
    // application-supplied strings independently.
    try O.checkIdentities(.{ .client = big[0..0xffff], .server = big[0..0xffff] }, big[0..0xffff]);
    try O.checkIdentities(.{}, "");
    try testing.expectError(error.IdentityTooLong, O.checkIdentities(.{ .client = big[0..0x10000] }, ""));
    try testing.expectError(error.IdentityTooLong, O.checkIdentities(.{ .server = big[0..0x10000] }, ""));
    try testing.expectError(error.IdentityTooLong, O.checkIdentities(.{}, big[0..0x10000]));
    try testing.expectError(error.IdentityTooLong, O.checkIdentities(.{ .client = big[0..0x10001] }, ""));
    try testing.expectError(error.IdentityTooLong, O.checkIdentities(.{ .server = big[0..0x10001] }, ""));
    try testing.expectError(error.IdentityTooLong, O.checkIdentities(.{}, big[0..0x10001]));
}

test "checkIdentities: 0xffff passes, 0x10000 fails, client / server / context each" {
    try checkBound(opaque_pake.Ristretto255Sha512);
    try checkBound(opaque_pake.P256Sha256);
}

test "generateKE3 and generateKE2 refuse an oversized server identity; generateKE3 also client and context" {
    const v = kat.real_1;
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    const server = try shim.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        .{ .client = v.client_identity, .server = v.server_identity },
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    try testing.expectError(error.IdentityTooLong, shim.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        .{ .server = big[0..0x10000] },
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    ));
    const ids = opaque_pake.Identities{ .client = v.client_identity, .server = v.server_identity };
    try testing.expectError(error.IdentityTooLong, shim.generateKE3(client.state, .{ .client = big[0..0x10000] }, v.context, server.ke2, .identity));
    try testing.expectError(error.IdentityTooLong, shim.generateKE3(client.state, .{ .server = big[0..0x10000] }, v.context, server.ke2, .identity));
    try testing.expectError(error.IdentityTooLong, shim.generateKE3(client.state, ids, big[0..0x10000], server.ke2, .identity));
    // Positive control: the same call with in-range strings succeeds.
    _ = try shim.generateKE3(client.state, ids, v.context, server.ke2, .identity);
}

test "a malformed evaluated element is InvalidMessage on both client paths (not InvalidBlind)" {
    const v = kat.real_1;
    const bad: [opaque_pake.Noe]u8 = @splat(0xff);
    try testing.expectError(error.InvalidMessage, shim.finalizeRegistrationRequest(
        v.password,
        v.blind_registration,
        .{ .evaluated_message = bad, .server_public_key = v.server_public_key },
        .{},
        v.envelope_nonce,
        .identity,
    ));
    const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
    const client = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
    var server = try shim.generateKE2(
        v.server_private_key,
        v.server_public_key,
        record,
        v.credential_identifier,
        v.oprf_seed,
        client.ke1,
        .{},
        v.context,
        v.masking_nonce,
        v.server_nonce,
        v.server_keyshare_seed,
    );
    server.ke2.credential_response.evaluated_message = bad;
    try testing.expectError(error.InvalidMessage, shim.generateKE3(client.state, .{}, v.context, server.ke2, .identity));
}
