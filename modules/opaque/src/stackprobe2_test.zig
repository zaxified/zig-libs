// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the two configurations
//! `stackprobe_test.zig` does not drive: `P256Sha256` and
//! `Ristretto255Sha512X25519` (curve25519 3DH). Same entry points, run on the
//! RFC 9807 Appendix C vectors (C.1.5 and C.1.3): the registration pair,
//! `generateKE1/KE2/KE3`, `serverFinish`. ReleaseFast/ReleaseSmall only
//! (`skipUnlessOptimized`).
//!
//! Needles are the secret inputs (password, blinds, `oprf_seed`, the server
//! key, both keyshare seeds) and the secret fields of every `out` (export key,
//! the client state's blind and ephemeral key, the server state's expected MAC
//! and session key, the session key); the engine's residue rule covers every
//! intermediate below each burn without naming it. The ristretto255
//! configuration keeps its hand-derived needle set in `stackprobe_test.zig`.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

fn field(v: anytype, name: []const u8) []const u8 {
    for (v.fields) |f| if (std.mem.eql(u8, f[0], name)) return f[1];
    @panic("missing vector field");
}

fn arr(comptime n: usize, v: anytype, name: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, field(v, name)) catch @panic("bad hex");
    return out;
}

fn Run(comptime O: type) type {
    return struct {
        // Every argument and `out` the probed calls see lives here (static).
        var pw_buf: [64]u8 = undefined;
        var cid_buf: [16]u8 = undefined;
        var ctx_buf: [16]u8 = undefined;
        var password: []const u8 = undefined;
        var cid: []const u8 = undefined;
        var context: []const u8 = undefined;
        var oprf_seed: [O.Nh]u8 = undefined;
        var fake: O.RegistrationRecord = undefined;

        fn rpW(pw: []const u8, b: *const [O.Ns]u8, e: *const [O.Noe]u8) ![O.Nx]u8 {
            return O.randomizedPassword(pw, b.*, e.*, O.Ksf.identity);
        }
        var server_sk: [O.Nsk]u8 = undefined;
        var server_pk: [O.Npk]u8 = undefined;
        var blind_reg: [O.Ns]u8 = undefined;
        var blind_login: [O.Ns]u8 = undefined;
        var client_seed: [O.Nseed]u8 = undefined;
        var server_seed: [O.Nseed]u8 = undefined;
        var request: O.RegistrationRequest = undefined;
        var response: O.RegistrationResponse = undefined;
        var reg: O.FinalizeRegistrationResult = undefined;
        var ke1: O.GenerateKE1Result = undefined;
        var ke2: O.GenerateKE2Result = undefined;
        var ke3: O.GenerateKE3Result = undefined;
        var server_session_key: [O.Nx]u8 = undefined;
        var fake_kp: O.AkeKeyPair = undefined;

        fn load(v: anytype) void {
            const pw = field(v, "password");
            password = std.fmt.hexToBytes(&pw_buf, pw) catch unreachable;
            cid = std.fmt.hexToBytes(&cid_buf, field(v, "credential_identifier")) catch unreachable;
            context = std.fmt.hexToBytes(&ctx_buf, field(v, "Context")) catch unreachable;
            oprf_seed = arr(O.Nh, v, "oprf_seed");
            server_sk = arr(O.Nsk, v, "server_private_key");
            server_pk = arr(O.Npk, v, "server_public_key");
            blind_reg = arr(O.Ns, v, "blind_registration");
            blind_login = arr(O.Ns, v, "blind_login");
            client_seed = arr(O.Nseed, v, "client_keyshare_seed");
            server_seed = arr(O.Nseed, v, "server_keyshare_seed");
        }

        fn probe(comptime name: []const u8, v: anytype) !void {
            load(v);
            const envelope_nonce = arr(O.Nn, v, "envelope_nonce");
            const client_nonce = arr(O.Nn, v, "client_nonce");
            const masking_nonce = arr(O.Nn, v, "masking_nonce");
            const server_nonce = arr(O.Nn, v, "server_nonce");
            const ids: O.Identities = .{};

            // Registration. The request and response are public messages;
            // `createRegistrationRequest` returns its request by value.
            _ = try P.run(name ++ " createRegistrationRequest", O.createRegistrationRequest, .{ password, &blind_reg }, &.{ password, &blind_reg }, .{});
            request = try O.createRegistrationRequest(password, &blind_reg);
            _ = try P.run(name ++ " createRegistrationResponse", O.createRegistrationResponse, .{ request, server_pk, cid, &oprf_seed }, &.{&oprf_seed}, .{});
            response = try O.createRegistrationResponse(request, server_pk, cid, &oprf_seed);
            _ = try P.run(name ++ " finalizeRegistrationRequest", O.finalizeRegistrationRequest, .{ password, &blind_reg, response, ids, envelope_nonce, O.Ksf.identity, &reg }, &.{ password, &blind_reg, &reg.export_key, &reg.record.masking_key }, .{});

            // Coverage sweep 2026-11-26: the registration-side helpers called on
            // their own. `randomizedPassword` returns its secret by value (into
            // the probe's call frame by shape) and takes `blind` by value: the
            // password is its needle, the residue rule the rest.
            _ = try P.run(name ++ " randomizedPassword", rpW, .{ password, &blind_reg, &response.evaluated_message }, &.{password}, .{});
            // mutation 2026-11-25: `fakeRecord` derives a key pair from `key_seed` (the private key is a
            // secret of the call, the seed the secret it comes from) and burns the stack after.
            try O.deriveAkeKeyPair(&server_seed, &fake_kp);
            _ = try P.run(name ++ " fakeRecord", O.fakeRecord, .{ &server_seed, &reg.record.masking_key, &fake }, &.{ &server_seed, &reg.record.masking_key, &fake_kp.private_key }, .{});
            try std.testing.expectEqualSlices(u8, &fake_kp.public_key, &fake.client_public_key);

            // Login, both sides.
            _ = try P.run(name ++ " generateKE1", O.generateKE1, .{ password, &blind_login, client_nonce, &client_seed, &ke1 }, &.{ password, &blind_login, &client_seed, &ke1.state.blind, &ke1.state.client_secret }, .{});
            _ = try P.run(name ++ " generateKE2", O.generateKE2, .{ &server_sk, server_pk, reg.record, cid, &oprf_seed, ke1.ke1, ids, context, masking_nonce, server_nonce, &server_seed, &ke2 }, &.{ &server_sk, &oprf_seed, &server_seed, &ke2.state.expected_client_mac, &ke2.state.session_key }, .{});
            _ = try P.run(name ++ " generateKE3", O.generateKE3, .{ &ke1.state, ids, context, ke2.ke2, O.Ksf.identity, &ke3 }, &.{ password, &ke1.state.blind, &ke1.state.client_secret, &ke3.session_key, &ke3.export_key }, .{});
            // Not `expected_client_mac` here: on success it equals the public
            // `ke3.client_mac` the call takes by value, so the needle matches
            // a copy of a wire message (it did, 127..143 B deep, above the
            // burn; without it the call is clean).
            _ = try P.run(name ++ " serverFinish", O.serverFinish, .{ &ke2.state, ke3.ke3, &server_session_key }, &.{ &ke2.state.session_key, &server_session_key }, .{});

            // The probed calls ran the protocol: both sides agree and match the RFC.
            try std.testing.expectEqualSlices(u8, &ke3.session_key, &server_session_key);
            try std.testing.expectEqualSlices(u8, &arr(O.Nx, v, "session_key"), &server_session_key);
            try std.testing.expectEqualSlices(u8, &reg.export_key, &ke3.export_key);
        }
    };
}

test "STACKPROBE: P256-SHA256 and ristretto255+X25519 registration and login leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    try Run(root.P256Sha256).probe("P256Sha256", @import("kat_vectors_p256.zig").real_5);
    try Run(root.Ristretto255Sha512X25519).probe("X25519", @import("kat_vectors_x25519.zig").real_3);
}
