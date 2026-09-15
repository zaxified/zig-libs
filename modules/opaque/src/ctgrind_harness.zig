// SPDX-License-Identifier: MIT

//! ctgrind_harness — `opaque`'s entry in the constant-time gate (A1
//! `opaque.md` M5). Run it through `../../../scripts/ctgrind.sh opaque`.
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
const kat = @import("kat_vectors.zig");
const memcheck = std.valgrind.memcheck;

const v = kat.real_1;

const Target = enum { register, login, serverke2 };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    inline for (@typeInfo(Target).@"enum".fields) |f| {
        if (std.mem.eql(u8, s, f.name)) return @field(Target, f.name);
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
            const request0 = try opaque_pake.createRegistrationRequest(v.password, v.blind_registration);
            const response = try opaque_pake.createRegistrationResponse(request0, v.server_public_key, v.credential_identifier, v.oprf_seed);

            taintBytes(v.password, &pw_buf, &pw, taint);
            var blind_buf: [32]u8 = undefined;
            var blind: [32]u8 = undefined;
            taintBytes(&v.blind_registration, &blind_buf, &blind, taint);

            // Measured.
            const request = try settle(opaque_pake.createRegistrationRequest(&pw, blind));
            const fin = try settle(opaque_pake.finalizeRegistrationRequest(&pw, blind, response, identities, v.envelope_nonce, .identity));

            std.debug.print("registration_request={x}\n", .{request.toBytes()});
            std.debug.print("registration_upload={x}\n", .{fin.record.toBytes()});
            std.debug.print("export_key={x}\n", .{fin.export_key});
        },
        .login => {
            // Untainted server side: KE2 for the honest KE1.
            const record = opaque_pake.RegistrationRecord.fromBytes(v.registration_upload);
            const client0 = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);
            const server = try opaque_pake.generateKE2(
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
            const client = try settle(opaque_pake.generateKE1(&pw, blind, v.client_nonce, seed));
            const fin = try settle(opaque_pake.generateKE3(client.state, identities, v.context, server.ke2, .identity));

            std.debug.print("ke1={x}\n", .{client.ke1.toBytes()});
            std.debug.print("ke3={x}\n", .{fin.ke3.toBytes()});
            std.debug.print("session_key={x}\n", .{fin.session_key});
            std.debug.print("export_key={x}\n", .{fin.export_key});
        },
        .serverke2 => {
            // Untainted client side.
            const client = try opaque_pake.generateKE1(v.password, v.blind_login, v.client_nonce, v.client_keyshare_seed);

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
            const server = try settle(opaque_pake.generateKE2(
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
    }
}
