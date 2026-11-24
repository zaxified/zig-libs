// SPDX-License-Identifier: MIT

//! ctgrind_harness — `opaque`'s entry in the constant-time gate (A1
//! `opaque.md` M5). Run it through `../../../scripts/checks/ctgrind.sh opaque`.
//!
//! NOT wired into `zig build test-opaque` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! Inputs are RFC 9807 Appendix C.1.1's vector (`kat_vectors.zig`), so every
//! printed value is a published one and the output pin is a KAT.
//!
//! ## Targets — ONE party's secrets each
//!
//! OPAQUE is two parties, and simulating both in one process with every
//! secret tainted would report the SERVER's handling of values that reached it
//! over the wire as if they were the client's secrets (the `dkg` over-taint
//! class). So each target runs the other party untainted first and taints only
//! what the measured party really holds:
//!
//! * `register`  — client: `password`, `blind` through
//!   `createRegistrationRequest` + `finalizeRegistrationRequest` (OPRF
//!   finalize, `randomized_password`, `Store`: key derivation, the client AKE
//!   key pair, the envelope MAC).
//! * `login`     — client: `password`, `blind`, `client_keyshare_seed` through
//!   `generateKE1` + `generateKE3` (`Recover`, unmasking, 3DH, the server MAC
//!   check).
//! * `serverke2` — server: `server_private_key`, `oprf_seed`,
//!   `server_keyshare_seed` and the stored record's `masking_key` through
//!   `generateKE2` (per-client OPRF key, blind evaluation, masking, 3DH, the
//!   key schedule).
//!
//! ## Verdicts are declassified, payloads are not
//!
//! Each call returns an error union whose TAG depends on secrets (the envelope
//! and server-MAC checks, the ~2^-252 zero-scalar cases). Branching on it in
//! the harness would be a context the harness invented. `settle` takes the
//! payload without a branch, checks the tag on a DECLASSIFIED copy (success or
//! failure of a login is exactly what the peer learns), and returns the
//! still-tainted payload, printed as the propagation witness.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless — the driver prints
//!    that as its own row.
//! 2. The inputs are comptime constants. `taintBytes` re-reads them through a
//!    volatile pointer after tainting, or the optimizer would fold the
//!    constants straight into the callee and the taint would never arrive.
//! 3. ReleaseFast only.

const std = @import("std");
const builtin = @import("builtin");
const opaque_pake = @import("root.zig");
const shim = @import("test_shim.zig");
const kat = @import("kat_vectors.zig");
const kat_p256 = @import("kat_vectors_p256.zig");
const kat_x25519 = @import("kat_vectors_x25519.zig");
const memcheck = std.valgrind.memcheck;

const v = kat.real_1;

const Target = enum {
    register,
    login,
    serverke2,
    register_p256,
    login_p256,
    serverke2_p256,
    register_x25519,
    login_x25519,
    serverke2_x25519,
};
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    inline for (@typeInfo(Target).@"enum".field_names) |name| {
        if (std.mem.eql(u8, s, name)) return @field(Target, name);
    }
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

/// Copies `src` into `buf`, marks it undefined (when tainting), and re-reads
/// it byte by byte through a volatile pointer into `out`.
fn taintBytes(src: []const u8, buf: []u8, out: []u8, taint: Taint) void {
    @memcpy(buf, src);
    if (taint == .yes) memcheck.makeMemUndefined(buf);
    for (out, buf) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
}

fn reloadVolatile(comptime T: type, s: *const T) T {
    const p: *const volatile T = s;
    return p.*;
}

/// The payload of `r`, without a branch on its tag; the tag itself is checked
/// on a declassified copy. See the module doc comment.
fn settle(r: anytype) !@typeInfo(@TypeOf(r)).error_union.payload {
    const payload = r catch undefined;
    var copy = r;
    memcheck.makeMemDefined(std.mem.asBytes(&copy));
    _ = try reloadVolatile(@TypeOf(r), &copy);
    return payload;
}

const identities: opaque_pake.Identities = .{ .client = v.client_identity, .server = v.server_identity };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const taint = try parseTaint(it.next() orelse return error.MissingTaint);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var pw_buf: [v.password.len]u8 = undefined;
    var pw: [v.password.len]u8 = undefined;

    switch (target) {
        .register => {
            // Untainted server side: its response to the honest request.
            const request0 = try shim.createRegistrationRequest(v.password, v.blind_registration);
            const response = try shim.createRegistrationResponse(request0, v.server_public_key, v.credential_identifier, v.oprf_seed);

            taintBytes(v.password, &pw_buf, &pw, taint);
            var blind_buf: [32]u8 = undefined;
            var blind: [32]u8 = undefined;
            taintBytes(&v.blind_registration, &blind_buf, &blind, taint);

            // Measured.
            const request = try settle(shim.createRegistrationRequest(&pw, blind));
            const fin = try settle(shim.finalizeRegistrationRequest(&pw, blind, response, identities, v.envelope_nonce, .identity));

            std.debug.print("registration_request={x}\n", .{request.toBytes()});
            std.debug.print("registration_upload={x}\n", .{fin.record.toBytes()});
            std.debug.print("export_key={x}\n", .{fin.export_key});
        },
        .login => {
            // Untainted server side: KE2 for the honest KE1.
            const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
            const client0 = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
            const server = try shim.generateKE2(
                v.server_private_key,
                v.server_public_key,
                record,
                v.credential_identifier,
                v.oprf_seed,
                client0.ke1,
                identities,
                v.context,
                v.masking_nonce,
                v.server_nonce,
                v.server_keyshare_seed,
            );

            taintBytes(v.password, &pw_buf, &pw, taint);
            var blind_buf: [32]u8 = undefined;
            var blind: [32]u8 = undefined;
            taintBytes(&v.blind_login, &blind_buf, &blind, taint);
            var seed_buf: [32]u8 = undefined;
            var seed: [32]u8 = undefined;
            taintBytes(&v.client_keyshare_seed, &seed_buf, &seed, taint);

            // Measured.
            const client = try settle(shim.generateKE1(&pw, blind, v.client_nonce, seed));
            const fin = try settle(shim.generateKE3(client.state, identities, v.context, server.ke2, .identity));

            std.debug.print("ke1={x}\n", .{client.ke1.toBytes()});
            std.debug.print("ke3={x}\n", .{fin.ke3.toBytes()});
            std.debug.print("session_key={x}\n", .{fin.session_key});
            std.debug.print("export_key={x}\n", .{fin.export_key});
        },
        .serverke2 => {
            // Untainted client side.
            const client = try shim.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);

            var sk_buf: [32]u8 = undefined;
            var sk: [32]u8 = undefined;
            taintBytes(&v.server_private_key, &sk_buf, &sk, taint);
            var oprf_buf: [64]u8 = undefined;
            var oprf_seed: [64]u8 = undefined;
            taintBytes(&v.oprf_seed, &oprf_buf, &oprf_seed, taint);
            var ks_buf: [32]u8 = undefined;
            var ks: [32]u8 = undefined;
            taintBytes(&v.server_keyshare_seed, &ks_buf, &ks, taint);
            // The stored record: only `masking_key` is secret. The client's
            // public key and the envelope are what the client uploaded.
            var record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
            var mk_buf: [64]u8 = undefined;
            taintBytes(&record.masking_key, &mk_buf, &record.masking_key, taint);

            // Measured.
            const server = try settle(shim.generateKE2(
                sk,
                v.server_public_key,
                record,
                v.credential_identifier,
                oprf_seed,
                client.ke1,
                identities,
                v.context,
                v.masking_nonce,
                v.server_nonce,
                ks,
            ));

            std.debug.print("ke2={x}\n", .{server.ke2.toBytes()});
            std.debug.print("session_key={x}\n", .{server.state.session_key});
        },
        .register_p256 => try runConfig(opaque_pake.P256Sha256, kat_p256.real_5, .register, taint),
        .login_p256 => try runConfig(opaque_pake.P256Sha256, kat_p256.real_5, .login, taint),
        .serverke2_p256 => try runConfig(opaque_pake.P256Sha256, kat_p256.real_5, .serverke2, taint),
        .register_x25519 => try runConfig(opaque_pake.Ristretto255Sha512X25519, kat_x25519.real_3, .register, taint),
        .login_x25519 => try runConfig(opaque_pake.Ristretto255Sha512X25519, kat_x25519.real_3, .login, taint),
        .serverke2_x25519 => try runConfig(opaque_pake.Ristretto255Sha512X25519, kat_x25519.real_3, .serverke2, taint),
    }
}

// ── the P256-SHA256 and curve25519-3DH configurations ──────────────────────
//
// The same three measurements over `opaque.P256Sha256` (RFC 9807 C.1.5) and
// `opaque.Ristretto255Sha512X25519` (C.1.3), through the pointer API
// directly. The vectors are hex fields looked up by name at run time; every
// secret input is tainted after decoding, so the decoder is not measured.

const Role = enum { register, login, serverke2 };

fn fieldOf(vec: anytype, name: []const u8) []const u8 {
    for (vec.fields) |f| if (std.mem.eql(u8, f[0], name)) return f[1];
    @panic("ctgrind_harness: missing vector field");
}

fn arr(comptime n: usize, vec: anytype, name: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, fieldOf(vec, name)) catch @panic("ctgrind_harness: bad hex");
    return out;
}

fn bytesOf(buf: []u8, vec: anytype, name: []const u8) []const u8 {
    const h = fieldOf(vec, name);
    return std.fmt.hexToBytes(buf[0 .. h.len / 2], h) catch @panic("ctgrind_harness: bad hex");
}

/// `n` bytes of `src`, tainted and re-read through a volatile pointer.
fn tainted(comptime n: usize, src: [n]u8, taint: Taint) [n]u8 {
    var buf: [n]u8 = undefined;
    var out: [n]u8 = undefined;
    taintBytes(&src, &buf, &out, taint);
    return out;
}

fn runConfig(comptime O: type, vec: anytype, role: Role, taint: Taint) !void {
    var pw_raw: [64]u8 = undefined;
    const password0 = bytesOf(&pw_raw, vec, "password");
    var cid_buf: [64]u8 = undefined;
    const credential_identifier = bytesOf(&cid_buf, vec, "credential_identifier");
    var ctx_buf: [64]u8 = undefined;
    const context = bytesOf(&ctx_buf, vec, "Context");
    const ids: O.Identities = .{ .client = null, .server = null };
    const oprf_seed0 = arr(O.Nh, vec, "oprf_seed");
    const server_public_key = arr(O.Npk, vec, "server_public_key");
    const server_private_key0 = arr(O.Nsk, vec, "server_private_key");
    const blind_registration0 = arr(O.Ns, vec, "blind_registration");
    const blind_login0 = arr(O.Ns, vec, "blind_login");
    const client_nonce = arr(O.Nn, vec, "client_nonce");
    const client_ks0 = arr(O.Nseed, vec, "client_keyshare_seed");
    const server_ks0 = arr(O.Nseed, vec, "server_keyshare_seed");
    const masking_nonce = arr(O.Nn, vec, "masking_nonce");
    const server_nonce = arr(O.Nn, vec, "server_nonce");
    const envelope_nonce = arr(O.Nn, vec, "envelope_nonce");

    // Untainted: the registration both sides agree on, and an honest KE1/KE2.
    const request0 = try O.createRegistrationRequest(password0, &blind_registration0);
    const response = try O.createRegistrationResponse(request0, server_public_key, credential_identifier, &oprf_seed0);
    var reg0: O.FinalizeRegistrationResult = undefined;
    try O.finalizeRegistrationRequest(password0, &blind_registration0, response, ids, envelope_nonce, .identity, &reg0);
    var ke1_0: O.GenerateKE1Result = undefined;
    try O.generateKE1(password0, &blind_login0, client_nonce, &client_ks0, &ke1_0);

    var pw_buf: [64]u8 = undefined;
    var pw_t: [64]u8 = undefined;
    taintBytes(password0, pw_buf[0..password0.len], pw_t[0..password0.len], if (role == .serverke2) .no else taint);
    const pw = pw_t[0..password0.len];

    switch (role) {
        .register => {
            const blind = tainted(O.Ns, blind_registration0, taint);
            const request = try settle(O.createRegistrationRequest(pw, &blind));
            var fin: O.FinalizeRegistrationResult = undefined;
            try settle(O.finalizeRegistrationRequest(pw, &blind, response, ids, envelope_nonce, .identity, &fin));
            std.debug.print("registration_request={x}\n", .{request.toBytes()});
            std.debug.print("registration_upload={x}\n", .{fin.record.toBytes()});
            std.debug.print("export_key={x}\n", .{fin.export_key});
        },
        .login => {
            var ke2: O.GenerateKE2Result = undefined;
            try O.generateKE2(&server_private_key0, server_public_key, reg0.record, credential_identifier, &oprf_seed0, ke1_0.ke1, ids, context, masking_nonce, server_nonce, &server_ks0, &ke2);
            const blind = tainted(O.Ns, blind_login0, taint);
            const seed = tainted(O.Nseed, client_ks0, taint);
            var ke1: O.GenerateKE1Result = undefined;
            try settle(O.generateKE1(pw, &blind, client_nonce, &seed, &ke1));
            var ke3: O.GenerateKE3Result = undefined;
            try settle(O.generateKE3(&ke1.state, ids, context, ke2.ke2, .identity, &ke3));
            std.debug.print("ke1={x}\n", .{ke1.ke1.toBytes()});
            std.debug.print("ke3={x}\n", .{ke3.ke3.toBytes()});
            std.debug.print("session_key={x}\n", .{ke3.session_key});
            std.debug.print("export_key={x}\n", .{ke3.export_key});
        },
        .serverke2 => {
            const sk = tainted(O.Nsk, server_private_key0, taint);
            const oprf_seed = tainted(O.Nh, oprf_seed0, taint);
            const ks = tainted(O.Nseed, server_ks0, taint);
            var record = reg0.record;
            record.masking_key = tainted(O.Nh, record.masking_key, taint);
            var ke2: O.GenerateKE2Result = undefined;
            try settle(O.generateKE2(&sk, server_public_key, record, credential_identifier, &oprf_seed, ke1_0.ke1, ids, context, masking_nonce, server_nonce, &ks, &ke2));
            std.debug.print("ke2={x}\n", .{ke2.ke2.toBytes()});
            std.debug.print("session_key={x}\n", .{ke2.state.session_key});
        },
    }
}
